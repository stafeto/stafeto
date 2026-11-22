/*
 * Mesa 3-D graphics library
 *
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * The EGL platform of stafeto: the windows of the composition service
 * (<stafeto/window.h>) as the native windows of EGL, drawn by the softpipe
 * driver through the swrast loader of the DRI frontend. The platform is
 * modelled on platform_surfaceless.c (the display without a device, the
 * pbuffer surfaces) and on the swrast path of platform_x11.c (a window
 * surface whose frames leave through the loader's putImage).
 *
 * The native window handle of EGL is the number of the window plus 1: Mesa's
 * eglCreateWindowSurface refuses the handle 0 before the platform is asked,
 * and the first window of a process is number 0.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/window.h>

#include "pipe/p_screen.h"
#include "util/format/u_format.h"

#include "dri_screen.h"
#include "dri_util.h"
#include "egl_dri2.h"
#include "egldevice.h"
#include "eglglobals.h"
#include "loader.h"
#include "swap.h"

/* The longest a swap waits for a free buffer (or, with a swap interval of 1,
 * for the service to take the frame): one second. */
#define WAIT_NS UINT64_C(1000000000)
/* The bytes of a point of both window formats. */
#define BYTES_PER_POINT 4

/* What a window surface holds besides the surface of Mesa. */
struct dri2_stafeto_surface {
   /* The window as it was when the surface was made, and its number. A window
    * closed and opened again shows as another description. */
   struct stafeto_window window;
   int number;
   /* The process that made the surface: a forked child has no window. */
   pid_t pid;
   struct swap_history history;
   /* The buffer last posted (-1 before the first swap): what the window shows,
    * and what getImage reads. */
   int shown;
   /* The swap under way: the buffer its frame goes to (-1 outside a swap),
    * the region of it that is copied and whether the copy was made. */
   int target;
   struct swap_rect copy;
   bool copied;
};

static uint64_t
now_ns(void)
{
   struct timespec t;

   clock_gettime(CLOCK_MONOTONIC, &t);
   return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

/* The window of the surface is open and is the one the surface was made for. */
static bool
stafeto_surface_is_the_window(const struct dri2_stafeto_surface *s)
{
   struct stafeto_window now;

   if (stafeto_window_info(s->number, &now) != 0)
      return false;
   return now.width == s->window.width && now.height == s->window.height &&
          now.stride == s->window.stride && now.format == s->window.format &&
          now.buffers == s->window.buffers &&
          memcmp(now.pixels, s->window.pixels, sizeof now.pixels) == 0;
}

/* Waits until a buffer of `mask` is free (the library's account), at most
 * until `deadline`. The index of the buffer, or -1 with errno: ETIMEDOUT,
 * ENODEV (the service is gone) or what the wait gave. A signal that ends the
 * wait goes on with it. */
static int
stafeto_wait_for_buffer(const struct dri2_stafeto_surface *s, uint32_t mask,
                        uint64_t deadline)
{
   for (;;) {
      uint32_t free = stafeto_window_free_buffers(s->number) & mask;
      uint32_t bits;
      uint64_t now;

      if (free)
         return __builtin_ctz(free);
      now = now_ns();
      if (now >= deadline) {
         errno = ETIMEDOUT;
         return -1;
      }
      if (stafeto_window_wait(s->number, deadline - now, &bits) == 0)
         continue;
      switch (errno) {
      case EINTR:
      case ETIMEDOUT:
         break;
      case EBUSY: {
         /* Another thread of the program waits on the window: look again soon. */
         struct timespec pause = {0, 1000000};

         nanosleep(&pause, NULL);
         break;
      }
      default:
         return -1;
      }
   }
}

static void
stafeto_get_drawable_info(struct dri_drawable *draw, int *x, int *y, int *w,
                          int *h, void *loaderPrivate)
{
   struct dri2_egl_surface *dri2_surf = loaderPrivate;

   *x = *y = 0;
   *w = dri2_surf->base.Width;
   *h = dri2_surf->base.Height;
}

/* The swap's copy: the frame of softpipe (rows from the top, `stride` bytes a
 * row, w by h points at (x, y)) into the free buffer the swap took, the part
 * the history says the buffer lacks. */
static void
stafeto_put_image2(struct dri_drawable *draw, int op, int x, int y, int w,
                   int h, int stride, char *data, void *loaderPrivate)
{
   struct dri2_egl_surface *dri2_surf = loaderPrivate;
   struct dri2_stafeto_surface *s = dri2_surf->stafeto;

   if (dri2_surf->base.Type != EGL_WINDOW_BIT) {
      /* A pbuffer: the rows go to the surface's own memory, one by one. */
      for (int i = 0; i < h; i++)
         swrast_pbuffer_loader_extension.putImage(draw, op, x, y + i, w, 1,
                                                  data + (size_t)i * stride,
                                                  loaderPrivate);
      return;
   }
   /* The window shows what a swap posts: other operations (drawing to the
    * front buffer) have nowhere to go. */
   if (op != __DRI_SWRAST_IMAGE_OP_SWAP || !s || s->target < 0)
      return;
   swap_blit(s->window.pixels[s->target], s->window.stride, s->window.width,
             s->window.height, (const unsigned char *)data, (size_t)stride, x, y,
             w, h, BYTES_PER_POINT, 0, s->copy);
   s->copied = true;
}

static void
stafeto_put_image(struct dri_drawable *draw, int op, int x, int y, int w, int h,
                  char *data, void *loaderPrivate)
{
   /* The rows of `data` are w points long. */
   stafeto_put_image2(draw, op, x, y, w, h, w * BYTES_PER_POINT, data,
                      loaderPrivate);
}

/* Reads what the window shows (the buffer last posted; black before the first
 * swap). The loader has no getImage2, so the driver keeps the front buffer of
 * a window as a texture of its own and asks for nothing; the rows of `data` are
 * w points long. */
static void
stafeto_get_image(struct dri_drawable *read, int x, int y, int w, int h,
                  char *data, void *loaderPrivate)
{
   struct dri2_egl_surface *dri2_surf = loaderPrivate;
   struct dri2_stafeto_surface *s = dri2_surf->stafeto;
   const int stride = w * BYTES_PER_POINT;

   if (dri2_surf->base.Type != EGL_WINDOW_BIT) {
      swrast_pbuffer_loader_extension.getImage(read, x, y, w, h, data,
                                               loaderPrivate);
      return;
   }
   for (int i = 0; i < h; i++) {
      char *row = data + (size_t)i * stride;
      int py = y + i;

      memset(row, 0, (size_t)w * BYTES_PER_POINT);
      if (!s || s->shown < 0 || py < 0 || py >= (int)s->window.height)
         continue;
      for (int j = 0; j < w; j++) {
         int px = x + j;

         if (px >= 0 && px < (int)s->window.width)
            memcpy(row + (size_t)j * BYTES_PER_POINT,
                   (const char *)s->window.pixels[s->shown] +
                      (size_t)py * s->window.stride +
                      (size_t)px * BYTES_PER_POINT,
                   BYTES_PER_POINT);
      }
   }
}

static const __DRIswrastLoaderExtension stafeto_swrast_loader_extension = {
   .getDrawableInfo = stafeto_get_drawable_info,
   .putImage = stafeto_put_image,
   .getImage = stafeto_get_image,
   .putImage2 = stafeto_put_image2,
};

/* The image loader of the platform surfaceless, for the pbuffers: the same
 * calls and the same answers. */
static struct dri_image *
stafeto_alloc_image(struct dri2_egl_display *dri2_dpy,
                    struct dri2_egl_surface *dri2_surf)
{
   return dri_create_image(
      dri2_dpy->dri_screen_render_gpu, dri2_surf->base.Width,
      dri2_surf->base.Height, dri2_surf->visual, NULL, 0, 0, NULL);
}

static int
stafeto_image_get_buffers(struct dri_drawable *driDrawable, unsigned int format,
                          uint32_t *stamp, void *loaderPrivate,
                          uint32_t buffer_mask, struct __DRIimageList *buffers)
{
   struct dri2_egl_surface *dri2_surf = loaderPrivate;
   struct dri2_egl_display *dri2_dpy =
      dri2_egl_display(dri2_surf->base.Resource.Display);

   buffers->image_mask = 0;
   buffers->front = NULL;
   buffers->back = NULL;

   /* A window has no images: the driver makes its buffers as textures of its
    * own, and a swap copies the frame out (stafeto_put_image2). Answering 0
    * says so; an answer of 1 with only a front image would leave the window
    * without a back buffer. */
   if (dri2_surf->base.Type == EGL_WINDOW_BIT)
      return 0;

   /* A pbuffer has a front buffer here, as in platform_surfaceless.c. */
   if (buffer_mask & __DRI_IMAGE_BUFFER_FRONT) {
      if (!dri2_surf->front) {
         dri2_surf->front = stafeto_alloc_image(dri2_dpy, dri2_surf);
         if (!dri2_surf->front)
            return 0;
      }
      buffers->image_mask |= __DRI_IMAGE_BUFFER_FRONT;
      buffers->front = dri2_surf->front;
   }
   return 1;
}

static void
stafeto_flush_front_buffer(struct dri_drawable *driDrawable, void *loaderPrivate)
{
}

static unsigned
stafeto_get_capability(void *loaderPrivate, enum dri_loader_cap cap)
{
   switch (cap) {
   case DRI_LOADER_CAP_FP16:
      return 1;
   case DRI_LOADER_CAP_RGBA_ORDERING:
      return 1;
   default:
      return 0;
   }
}

static const __DRIimageLoaderExtension stafeto_image_loader_extension = {
   .getBuffers = stafeto_image_get_buffers,
   .flushFrontBuffer = stafeto_flush_front_buffer,
   .getCapability = stafeto_get_capability,
};

static const struct dri_loader_funcs stafeto_loader_funcs = {
   .image_lookup = &image_lookup_extension,
   .image = &stafeto_image_loader_extension,
   .swrast = &stafeto_swrast_loader_extension,
};

static void
stafeto_free_pbuffer_images(struct dri2_egl_surface *dri2_surf)
{
   if (dri2_surf->front) {
      dri2_destroy_image(dri2_surf->front);
      dri2_surf->front = NULL;
   }
   free(dri2_surf->swrast_device_buffer);
   dri2_surf->swrast_device_buffer = NULL;
}

static _EGLSurface *
dri2_stafeto_create_pbuffer_surface(_EGLDisplay *disp, _EGLConfig *conf,
                                    const EGLint *attrib_list)
{
   struct dri2_egl_display *dri2_dpy = dri2_egl_display(disp);
   struct dri2_egl_config *dri2_conf = dri2_egl_config(conf);
   struct dri2_egl_surface *dri2_surf;
   const struct dri_config *config;

   dri2_surf = calloc(1, sizeof *dri2_surf);
   if (!dri2_surf) {
      _eglError(EGL_BAD_ALLOC, "eglCreatePbufferSurface");
      return NULL;
   }

   if (!dri2_init_surface(&dri2_surf->base, disp, EGL_PBUFFER_BIT, conf,
                          attrib_list, false, NULL))
      goto cleanup_surface;

   config = dri2_get_dri_config(dri2_conf, EGL_PBUFFER_BIT,
                                dri2_surf->base.GLColorspace);
   if (!config) {
      _eglError(EGL_BAD_MATCH,
                "Unsupported surfacetype/colorspace configuration");
      goto cleanup_surface;
   }

   dri2_surf->visual = dri2_image_format_for_pbuffer_config(dri2_dpy, config);
   if (dri2_surf->visual == PIPE_FORMAT_NONE)
      goto cleanup_surface;

   if (!dri2_create_drawable(dri2_dpy, config, dri2_surf, dri2_surf))
      goto cleanup_surface;

   return &dri2_surf->base;

cleanup_surface:
   free(dri2_surf);
   return NULL;
}

/* eglCreateWindowSurface: `native_window` is the number of the window plus 1. */
static _EGLSurface *
dri2_stafeto_create_window_surface(_EGLDisplay *disp, _EGLConfig *conf,
                                   void *native_window,
                                   const EGLint *attrib_list)
{
   struct dri2_egl_display *dri2_dpy = dri2_egl_display(disp);
   struct dri2_egl_config *dri2_conf = dri2_egl_config(conf);
   struct dri2_egl_surface *dri2_surf;
   struct dri2_stafeto_surface *s;
   const struct dri_config *config;
   struct stafeto_window window;
   uintptr_t handle = (uintptr_t)native_window;

   if (handle == 0 || handle - 1 > (uintptr_t)INT_MAX ||
       stafeto_window_info((int)(handle - 1), &window) != 0) {
      _eglError(EGL_BAD_NATIVE_WINDOW, "eglCreateWindowSurface");
      return NULL;
   }
   /* The configuration says the format of the points the window holds. */
   if ((uint32_t)conf->NativeVisualID != window.format) {
      _eglError(EGL_BAD_MATCH, "eglCreateWindowSurface: the format of the window");
      return NULL;
   }
   /* A swap takes a free buffer and the one buffer of a window never comes back. */
   if (window.buffers < 2) {
      _eglError(EGL_BAD_NATIVE_WINDOW,
                "eglCreateWindowSurface: the window has one buffer");
      return NULL;
   }

   dri2_surf = calloc(1, sizeof *dri2_surf);
   s = calloc(1, sizeof *s);
   if (!dri2_surf || !s) {
      free(dri2_surf);
      free(s);
      _eglError(EGL_BAD_ALLOC, "eglCreateWindowSurface");
      return NULL;
   }
   dri2_surf->stafeto = s;
   s->window = window;
   s->number = (int)(handle - 1);
   s->pid = getpid();
   s->shown = -1;
   s->target = -1;
   swap_history_init(&s->history, (int)window.width, (int)window.height,
                     window.buffers);

   if (!dri2_init_surface(&dri2_surf->base, disp, EGL_WINDOW_BIT, conf,
                          attrib_list, false, native_window))
      goto cleanup_surface;

   config = dri2_get_dri_config(dri2_conf, EGL_WINDOW_BIT,
                                dri2_surf->base.GLColorspace);
   if (!config) {
      _eglError(EGL_BAD_MATCH,
                "Unsupported surfacetype/colorspace configuration");
      goto cleanup_surface;
   }

   dri2_surf->base.Width = (EGLint)window.width;
   dri2_surf->base.Height = (EGLint)window.height;
   dri2_surf->base.SwapInterval = dri2_dpy->default_swap_interval;

   if (!dri2_create_drawable(dri2_dpy, config, dri2_surf, dri2_surf))
      goto cleanup_surface;

   return &dri2_surf->base;

cleanup_surface:
   free(s);
   free(dri2_surf);
   return NULL;
}

static EGLBoolean
dri2_stafeto_destroy_surface(_EGLDisplay *disp, _EGLSurface *surf)
{
   struct dri2_egl_surface *dri2_surf = dri2_egl_surface(surf);

   if (surf->Type == EGL_PBUFFER_BIT)
      stafeto_free_pbuffer_images(dri2_surf);
   driDestroyDrawable(dri2_surf->dri_drawable);
   free(dri2_surf->stafeto);
   dri2_fini_surface(surf);
   free(dri2_surf);
   return EGL_TRUE;
}

/* eglSwapBuffers and eglSwapBuffersWithDamage*: one copy of the frame into a
 * free buffer of the window and one POST (docs/egl.md). */
static EGLBoolean
dri2_stafeto_swap_buffers(_EGLDisplay *disp, _EGLSurface *draw,
                          const EGLint *rects, EGLint n_rects)
{
   struct dri2_egl_surface *dri2_surf = dri2_egl_surface(draw);
   struct dri2_stafeto_surface *s = dri2_surf->stafeto;
   struct swap_plan plan;
   struct stafeto_rect post[SWAP_POST_MAX];
   uint64_t deadline;
   int buffer, before;

   /* A forked child has no window; the surface is the parent's. */
   if (s->pid != getpid())
      return _eglError(EGL_BAD_SURFACE, "eglSwapBuffers: the window belongs to the parent");
   if (!stafeto_surface_is_the_window(s))
      return _eglError(EGL_BAD_NATIVE_WINDOW, "eglSwapBuffers: the window is gone");

   deadline = now_ns() + WAIT_NS;
   buffer = stafeto_wait_for_buffer(s, (1u << s->window.buffers) - 1, deadline);
   if (buffer < 0)
      return _eglError(EGL_BAD_NATIVE_WINDOW, "eglSwapBuffers: no free buffer");

   swap_plan_make(&s->history, (unsigned)buffer, rects, n_rects, &plan);
   s->target = buffer;
   s->copy = plan.copy;
   s->copied = false;
   driSwapBuffers(dri2_surf->dri_drawable, 0, NULL);
   s->target = -1;
   if (!s->copied && !swap_rect_empty(plan.copy))
      _eglLog(_EGL_WARNING, "eglSwapBuffers: the driver put no image");

   for (unsigned i = 0; i < plan.post_count; i++) {
      post[i].x = plan.post[i].x;
      post[i].y = plan.post[i].y;
      post[i].w = plan.post[i].w;
      post[i].h = plan.post[i].h;
   }
   if (stafeto_window_post(s->number, (uint32_t)buffer, post, plan.post_count) != 0) {
      /* The service did not take the frame: the next swap starts whole. */
      swap_history_reset(&s->history);
      return _eglError(EGL_BAD_NATIVE_WINDOW, "eglSwapBuffers: the post failed");
   }
   before = s->shown;
   s->shown = buffer;

   /* An interval of 1 waits until the service takes the frame into one of its
    * own, which frees the buffer the window showed before. A frame that is
    * late is no error. */
   if (draw->SwapInterval > 0 && before >= 0 && before != buffer) {
      int got = stafeto_wait_for_buffer(s, 1u << before, now_ns() + WAIT_NS);

      if (got < 0 && errno == ENODEV)
         return _eglError(EGL_BAD_NATIVE_WINDOW, "eglSwapBuffers: the service is gone");
   }
   return EGL_TRUE;
}

static EGLBoolean
dri2_stafeto_swap_interval(_EGLDisplay *disp, _EGLSurface *surf, EGLint interval)
{
   /* The common code has clamped it to the configuration's 0 and 1, and a swap
    * reads it from the surface. */
   return EGL_TRUE;
}

static const struct dri2_egl_display_vtbl dri2_stafeto_display_vtbl = {
   .create_window_surface = dri2_stafeto_create_window_surface,
   .create_pbuffer_surface = dri2_stafeto_create_pbuffer_surface,
   .destroy_surface = dri2_stafeto_destroy_surface,
   .swap_interval = dri2_stafeto_swap_interval,
   .swap_buffers = dri2_stafeto_swap_buffers,
   .create_image = dri2_create_image_khr,
};

/* The configurations: the two formats of a window (the points of the format
 * are what softpipe's BGRA8888 and BGRX8888 hold), no multisampling, the
 * depths and stencils 0 and 0, 16 and 0, 24 and 8. Every one serves window
 * surfaces (the double-buffered driver configuration) and pbuffers (the
 * single-buffered one). */
static void
stafeto_add_configs(_EGLDisplay *disp)
{
   struct dri2_egl_display *dri2_dpy = dri2_egl_display(disp);

   for (unsigned i = 0; dri2_dpy->driver_configs[i] != NULL; i++) {
      const struct gl_config *gl = (const struct gl_config *)dri2_dpy->driver_configs[i];
      EGLint format;

      if (gl->color_format == PIPE_FORMAT_BGRA8888_UNORM)
         format = STAFETO_WINDOW_ARGB8888;
      else if (gl->color_format == PIPE_FORMAT_BGRX8888_UNORM)
         format = STAFETO_WINDOW_XRGB8888;
      else
         continue;
      if (gl->samples > 1)
         continue;
      if (!((gl->depthBits == 0 && gl->stencilBits == 0) ||
            (gl->depthBits == 16 && gl->stencilBits == 0) ||
            (gl->depthBits == 24 && gl->stencilBits == 8)))
         continue;

      const EGLint attrs[] = {
         EGL_NATIVE_VISUAL_ID, format,
         EGL_NONE,
      };

      dri2_add_config(disp, dri2_dpy->driver_configs[i],
                      EGL_WINDOW_BIT | EGL_PBUFFER_BIT |
                         EGL_SWAP_BEHAVIOR_PRESERVED_BIT,
                      attrs);
   }
}

EGLBoolean
dri2_initialize_stafeto(_EGLDisplay *disp)
{
   struct dri2_egl_display *dri2_dpy = dri2_egl_display(disp);
   struct _egl_device *device;
   const char *err;

   /* No device and no list of devices: softpipe draws with the processor. */
   device = _eglFindDevice(dri2_dpy->fd_render_gpu, true);
   dri2_dpy->fd_render_gpu = -1;
   if (_eglHasAttrib(disp, EGL_DEVICE_EXT) && disp->Device != device) {
      err = "DRI2: the device is not the software one";
      goto cleanup;
   }
   disp->Device = device;
   dri2_dpy->driver_name = strdup("swrast");
   if (!dri2_dpy->driver_name) {
      err = "DRI2: out of memory";
      goto cleanup;
   }
   dri2_detect_swrast_kopper(disp);
   dri2_dpy->loader_funcs = &stafeto_loader_funcs;
   dri2_dpy->fd_display_gpu = dri2_dpy->fd_render_gpu;

   if (!dri2_create_screen(disp)) {
      err = "DRI2: failed to create screen";
      goto cleanup;
   }

   dri2_setup_screen(disp);
   /* Swap intervals 0 and 1: the service takes the latest frame (0), or the
    * swap waits until it took the last (1). */
   dri2_setup_swap_interval(disp, 1);
   disp->Extensions.EXT_swap_buffers_with_damage = EGL_TRUE;

   stafeto_add_configs(disp);

   /* Fill vtbl last to prevent accidentally calling virtual function during
    * initialization.
    */
   dri2_dpy->vtbl = &dri2_stafeto_display_vtbl;
   return EGL_TRUE;

cleanup:
   return _eglError(EGL_NOT_INITIALIZED, err);
}
