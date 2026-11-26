// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#include "tcuStafetoPlatform.hpp"

#include "egluGLContextFactory.hpp"
#include "egluNativeDisplay.hpp"
#include "egluNativePixmap.hpp"
#include "egluNativeWindow.hpp"
#include "eglwEnums.hpp"
#include "eglwFunctions.hpp"
#include "eglwLibrary.hpp"
#include "tcuDefs.hpp"
#include "tcuVector.hpp"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <stafeto/window.h>

namespace tcu
{
namespace stafeto
{
namespace
{

// A window of the composition service as a native window of EGL. The
// process has one window at a time: a second open fails with a resource
// error (the tests that hold two windows wait for the window manager). The
// protocol has no resize and no visibility, so those capabilities are left
// out and the tests that need them report NotSupported.
class Window : public eglu::NativeWindow
{
public:
    static const Capability CAPABILITIES = Capability(CAPABILITY_CREATE_SURFACE_LEGACY | CAPABILITY_GET_SURFACE_SIZE |
                                                      CAPABILITY_GET_SCREEN_SIZE);

    Window(const eglu::WindowParams &params, uint32_t format) : NativeWindow(CAPABILITIES), m_number(-1)
    {
        stafeto_screen screen;
        memset(&screen, 0, sizeof screen);
        if (stafeto_screen_describe(&screen) != 0)
            throw ResourceError(std::string("stafeto_screen_describe failed: ") + strerror(errno));
        const int width  = params.width == eglu::WindowParams::SIZE_DONT_CARE ? 64 : params.width;
        const int height = params.height == eglu::WindowParams::SIZE_DONT_CARE ? 64 : params.height;
        if (width <= 0 || height <= 0 || uint32_t(width) > screen.width || uint32_t(height) > screen.height)
            throw NotSupportedError("window larger than the screen");
        // Two buffers: a swap needs a free one, and a window of one never gets it back.
        memset(&m_info, 0, sizeof m_info);
        m_number = stafeto_window_open(0, 0, width, height, format, 2, 0, &m_info);
        if (m_number < 0)
            throw ResourceError(std::string("stafeto_window_open failed: ") + strerror(errno));
    }

    ~Window()
    {
        if (m_number >= 0)
            stafeto_window_close(m_number);
    }

    // The number of the window plus 1: the handle 0 stays "no window".
    eglw::EGLNativeWindowType getLegacyNative()
    {
        return (eglw::EGLNativeWindowType)(uintptr_t)(m_number + 1);
    }

    IVec2 getSurfaceSize() const
    {
        return IVec2(int(m_info.width), int(m_info.height));
    }

    IVec2 getScreenSize() const
    {
        return getSurfaceSize();
    }

    // Takes the events the service queues for the window, so that its ring
    // never fills; the tests use none.
    void processEvents()
    {
        uint32_t bits = 0;
        if (stafeto_window_wait(m_number, 0, &bits) == 0 && (bits & STAFETO_WINDOW_EVENTS))
        {
            stafeto_window_event events[STAFETO_WINDOW_EVENTS_MAX];
            uint32_t flags = 0;
            stafeto_window_events(m_number, events, STAFETO_WINDOW_EVENTS_MAX, &flags);
        }
    }

private:
    int m_number;
    stafeto_window m_info;
};

// A pixmap with the handle of nullptr, as the platform nullws of dEQP has it:
// the platform of EGL refuses pixmap surfaces (EGL_BAD_NATIVE_PIXMAP, no
// EGL_PIXMAP_BIT), so the tests of the negative API reach EGL with it, and the
// tests that need a working pixmap find the surface refused.
class Pixmap : public eglu::NativePixmap
{
public:
    static const Capability CAPABILITIES = CAPABILITY_CREATE_SURFACE_LEGACY;

    Pixmap() : NativePixmap(CAPABILITIES)
    {
    }

    eglw::EGLNativePixmapType getLegacyNative()
    {
        return nullptr;
    }
};

class PixmapFactory : public eglu::NativePixmapFactory
{
public:
    PixmapFactory() : NativePixmapFactory("stafeto", "Pixmap stub of stafeto", Pixmap::CAPABILITIES)
    {
    }

    eglu::NativePixmap *createPixmap(eglu::NativeDisplay *, int, int) const
    {
        return new Pixmap();
    }
};

class Display : public eglu::NativeDisplay
{
public:
    static const Capability CAPABILITIES = CAPABILITY_GET_DISPLAY_LEGACY;

    Display() : eglu::NativeDisplay(CAPABILITIES), m_library(nullptr)
    {
    }

    eglw::EGLNativeDisplayType getLegacyNative()
    {
        return EGL_DEFAULT_DISPLAY;
    }

    // The entry points of EGL are linked in (no dlopen): the library asks
    // the program's own table.
    const eglw::Library &getLibrary() const
    {
        return m_library;
    }

private:
    eglw::DefaultLibrary m_library;
};

class WindowFactory : public eglu::NativeWindowFactory
{
public:
    WindowFactory() : NativeWindowFactory("stafeto", "Window of the composition service", Window::CAPABILITIES)
    {
    }

    eglu::NativeWindow *createWindow(eglu::NativeDisplay *, const eglu::WindowParams &params) const
    {
        return new Window(params, STAFETO_WINDOW_XRGB8888);
    }

    // The format of the window is the native visual of the configuration.
    eglu::NativeWindow *createWindow(eglu::NativeDisplay *nativeDisplay, eglw::EGLDisplay display,
                                     eglw::EGLConfig config, const eglw::EGLAttrib *,
                                     const eglu::WindowParams &params) const
    {
        eglw::EGLint visual = STAFETO_WINDOW_XRGB8888;
        nativeDisplay->getLibrary().getConfigAttrib(display, config, EGL_NATIVE_VISUAL_ID, &visual);
        return new Window(params, uint32_t(visual));
    }
};

class DisplayFactory : public eglu::NativeDisplayFactory
{
public:
    DisplayFactory() : eglu::NativeDisplayFactory("stafeto", "Display of stafeto", Display::CAPABILITIES)
    {
        m_nativeWindowRegistry.registerFactory(new WindowFactory());
        m_nativePixmapRegistry.registerFactory(new PixmapFactory());
    }

    eglu::NativeDisplay *createDisplay(const eglw::EGLAttrib * = nullptr) const
    {
        return new Display();
    }
};

} // namespace

Platform::Platform()
{
    m_nativeDisplayFactoryRegistry.registerFactory(new DisplayFactory());
    m_contextFactoryRegistry.registerFactory(new eglu::GLContextFactory(m_nativeDisplayFactoryRegistry));
}

Platform::~Platform()
{
}

} // namespace stafeto
} // namespace tcu

tcu::Platform *createPlatform()
{
    return new tcu::stafeto::Platform();
}
