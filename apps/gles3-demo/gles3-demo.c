/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The field of cubes of stafeto: a C program on EGL 1.5 and OpenGL ES 3.0
 * (<EGL/egl.h>, <GLES3/gl3.h>), which Mesa's softpipe driver runs on the
 * processor. It uses what OpenGL ES 3 adds to the cube of gles-cube.c: a vertex
 * array object that holds the whole state of the vertex arrays, a uniform block
 * (std140) with the matrices, the light and a palette, and one instanced draw
 * (glDrawElementsInstanced) of 64 cubes, whose place comes from gl_InstanceID
 * and whose tint from an attribute with a divisor of 1.
 *
 * `gles3-demo --probe` draws the frames twice: into a pbuffer surface first,
 * and for each frame prints the CRC-32 (the one of zlib) and the sum of the
 * bytes of the glReadPixels image (rows from the bottom up, the way GL returns
 * them); then into a window of the composition service (<stafeto/window.h>),
 * where each frame, read back and swapped, must have the CRC of the frame of the
 * pbuffer and the rows of the window must be the mirror of the readback. The
 * program prints the CRC-32 of the points of the window as the host takes it from
 * a screenshot (red, green, blue of each point, rows from the top) and, with
 * --hold FD, writes a byte to the descriptor FD and keeps the window until it is
 * killed: the holder of a scene (wfc-demo --gles) shows the window and the host
 * compares its screenshot with that CRC.
 *
 * Options: --probe (required), --size N (the side, default 160), --frames N
 * (1 to 3, default 3: a window has three buffers and nothing frees them while
 * no scene shows the window), --hold FD. The angles of the frames are tables
 * in the program, so the picture does not depend on the math library of the
 * system. Built with -fno-builtin; every result is compared.
 */

#define _POSIX_C_SOURCE 200809L

#include <EGL/egl.h>
#include <GLES3/gl3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/window.h>

#include "swap.h"

#define FRAMES_MAX 3
#define INSTANCES 64
#define SCREEN_W 640
#define SCREEN_H 400
#define WINDOW_BUFFERS 3

/* Sine and cosine of the spin of each frame about Z: 0, 25 and 50 degrees. */
static const float SIN_Z[FRAMES_MAX] = {0.000000000f, 0.422618262f, 0.766044443f};
static const float COS_Z[FRAMES_MAX] = {1.000000000f, 0.906307787f, 0.642787610f};
/* The tilt of the field about X, 55 degrees. */
static const float SIN_X = 0.819152044f;
static const float COS_X = 0.573576436f;

static const char VERTEX_SHADER[] =
	"#version 300 es\n"
	"layout(std140) uniform Scene {\n"
	"  mat4 model;\n"
	"  mat4 viewproj;\n"
	"  vec4 light;\n"
	"  vec4 palette[4];\n"
	"};\n"
	"layout(location = 0) in vec3 position;\n"
	"layout(location = 1) in vec3 normal;\n"
	"layout(location = 2) in vec3 tint;\n"
	"out vec3 v_colour;\n"
	"out float v_light;\n"
	"void main() {\n"
	"  float i = float(gl_InstanceID);\n"
	"  vec3 offset = vec3(mod(i, 8.0) - 3.5, floor(i / 8.0) - 3.5, 0.0);\n"
	"  gl_Position = viewproj * (model * vec4(position * 0.38 + offset, 1.0));\n"
	"  v_light = max(dot(mat3(model) * normal, light.xyz), 0.0);\n"
	"  v_colour = mix(tint, palette[gl_InstanceID % 4].rgb, 0.5);\n"
	"}\n";

static const char FRAGMENT_SHADER[] =
	"#version 300 es\n"
	"precision mediump float;\n"
	"in vec3 v_colour;\n"
	"in float v_light;\n"
	"out vec4 frag;\n"
	"void main() {\n"
	"  frag = vec4(v_colour * (0.25 + 0.75 * v_light), 1.0);\n"
	"}\n";

/* The std140 block: two matrices, the light and four colours, 208 bytes. */
struct scene_block {
	float model[16];
	float viewproj[16];
	float light[4];
	float palette[4][4];
};

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			printf("gles3-demo: check failed at line %d: %s (egl 0x%x gl 0x%x)\n", __LINE__, #cond, \
			       (unsigned)eglGetError(), (unsigned)glGetError()); \
			exit(1); \
		} \
	} while (0)

static uint32_t crc_table[256];

static void crc_init(void)
{
	for (uint32_t n = 0; n < 256; n++) {
		uint32_t c = n;
		for (int k = 0; k < 8; k++)
			c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
		crc_table[n] = c;
	}
}

static uint32_t crc_update(uint32_t c, const uint8_t *data, size_t length)
{
	for (size_t i = 0; i < length; i++)
		c = crc_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
	return c;
}

/* c = a * b, all column-major 4 x 4. */
static void mat4_mul(float *c, const float *a, const float *b)
{
	for (int col = 0; col < 4; col++)
		for (int row = 0; row < 4; row++) {
			float sum = 0;
			for (int k = 0; k < 4; k++)
				sum += a[k * 4 + row] * b[col * 4 + k];
			c[col * 4 + row] = sum;
		}
}

static GLuint compile(GLenum kind, const char *source)
{
	GLuint shader = glCreateShader(kind);
	CHECK(shader != 0);
	glShaderSource(shader, 1, &source, NULL);
	glCompileShader(shader);
	GLint status = 0;
	glGetShaderiv(shader, GL_COMPILE_STATUS, &status);
	if (!status) {
		char log[512];
		GLsizei length = 0;
		glGetShaderInfoLog(shader, sizeof log - 1, &length, log);
		log[length] = 0;
		printf("gles3-demo: shader did not compile: %s\n", log);
		exit(1);
	}
	return shader;
}

static void print_string(const char *label, GLenum name)
{
	const GLubyte *text = glGetString(name);
	printf("gles3-demo: %s %s\n", label, text ? (const char *)text : "(none)");
}

static EGLint config_value(EGLDisplay display, EGLConfig config, EGLint attribute)
{
	EGLint value = -1;
	CHECK(eglGetConfigAttrib(display, config, attribute, &value) == EGL_TRUE);
	return value;
}

/* The first configuration of OpenGL ES 3 with 8 bits of each colour and none
 * of alpha, a 16-bit depth buffer, windows and pbuffers both. */
static EGLConfig choose_config(EGLDisplay display)
{
	EGLConfig all[64];
	EGLint count = 0;
	CHECK(eglGetConfigs(display, all, 64, &count) == EGL_TRUE);
	for (EGLint i = 0; i < count; i++) {
		EGLint types = config_value(display, all[i], EGL_SURFACE_TYPE);
		if ((types & EGL_WINDOW_BIT) && (types & EGL_PBUFFER_BIT) &&
		    (config_value(display, all[i], EGL_RENDERABLE_TYPE) & EGL_OPENGL_ES3_BIT) &&
		    config_value(display, all[i], EGL_RED_SIZE) == 8 &&
		    config_value(display, all[i], EGL_GREEN_SIZE) == 8 &&
		    config_value(display, all[i], EGL_BLUE_SIZE) == 8 &&
		    config_value(display, all[i], EGL_ALPHA_SIZE) == 0 &&
		    config_value(display, all[i], EGL_DEPTH_SIZE) == 16)
			return all[i];
	}
	CHECK(0);
	return NULL;
}

static GLuint vao, instance_buffer, scene_buffer;
static GLsizei index_count;

/* The program, the buffers and the vertex array object. */
static void setup(void)
{
	GLuint program = glCreateProgram();
	glAttachShader(program, compile(GL_VERTEX_SHADER, VERTEX_SHADER));
	glAttachShader(program, compile(GL_FRAGMENT_SHADER, FRAGMENT_SHADER));
	glLinkProgram(program);
	GLint linked = 0;
	glGetProgramiv(program, GL_LINK_STATUS, &linked);
	CHECK(linked);
	glUseProgram(program);

	/* The uniform block: the size std140 gives it, bound to point 0. */
	GLuint block = glGetUniformBlockIndex(program, "Scene");
	CHECK(block != GL_INVALID_INDEX);
	GLint block_size = 0;
	glGetActiveUniformBlockiv(program, block, GL_UNIFORM_BLOCK_DATA_SIZE, &block_size);
	CHECK(block_size == (GLint)sizeof(struct scene_block));
	glUniformBlockBinding(program, block, 0);
	glGenBuffers(1, &scene_buffer);
	glBindBuffer(GL_UNIFORM_BUFFER, scene_buffer);
	glBufferData(GL_UNIFORM_BUFFER, sizeof(struct scene_block), NULL, GL_DYNAMIC_DRAW);
	glBindBufferBase(GL_UNIFORM_BUFFER, 0, scene_buffer);
	printf("gles3-demo: uniform block Scene of %d bytes\n", (int)block_size);

	/* A cube of 24 vertices (position, normal) and 36 indices. */
	static float cube[24 * 6];
	static uint16_t indices[36];
	for (int face = 0; face < 6; face++) {
		int axis = face / 2;
		float sign = (face % 2) ? -1.0f : 1.0f;
		int u = (axis + 1) % 3, v = (axis + 2) % 3;
		static const float CORNER[4][2] = {{-1, -1}, {1, -1}, {1, 1}, {-1, 1}};
		for (int k = 0; k < 4; k++) {
			float *vertex = cube + (face * 4 + k) * 6;
			vertex[axis] = sign;
			vertex[u] = CORNER[k][0];
			vertex[v] = CORNER[k][1];
			vertex[3 + axis] = sign;
		}
		static const uint16_t FRONT[6] = {0, 1, 2, 0, 2, 3};
		static const uint16_t BACK[6] = {0, 2, 1, 0, 3, 2};
		for (int k = 0; k < 6; k++)
			indices[face * 6 + k] = (uint16_t)(face * 4 + (sign > 0 ? FRONT[k] : BACK[k]));
	}
	index_count = 36;

	/* The tint of each instance, from integers so every machine agrees. */
	static float tints[INSTANCES * 3];
	for (int i = 0; i < INSTANCES; i++) {
		tints[i * 3 + 0] = 0.3f + 0.6f * (float)((i * 5) % 8) / 7.0f;
		tints[i * 3 + 1] = 0.3f + 0.6f * (float)((i * 3 + i / 8) % 8) / 7.0f;
		tints[i * 3 + 2] = 0.3f + 0.6f * (float)((i * 7 + 3) % 8) / 7.0f;
	}

	/* The vertex array object keeps the three attributes, the divisor of the
	 * tint and the element buffer. */
	GLuint buffers[2];
	glGenVertexArrays(1, &vao);
	CHECK(vao != 0);
	glBindVertexArray(vao);
	glGenBuffers(2, buffers);
	glBindBuffer(GL_ARRAY_BUFFER, buffers[0]);
	glBufferData(GL_ARRAY_BUFFER, sizeof cube, cube, GL_STATIC_DRAW);
	glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, buffers[1]);
	glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof indices, indices, GL_STATIC_DRAW);
	glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 6 * sizeof(float), (const void *)0);
	glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, 6 * sizeof(float), (const void *)(3 * sizeof(float)));
	glEnableVertexAttribArray(0);
	glEnableVertexAttribArray(1);
	glGenBuffers(1, &instance_buffer);
	glBindBuffer(GL_ARRAY_BUFFER, instance_buffer);
	glBufferData(GL_ARRAY_BUFFER, sizeof tints, tints, GL_STATIC_DRAW);
	glVertexAttribPointer(2, 3, GL_FLOAT, GL_FALSE, 3 * sizeof(float), (const void *)0);
	glEnableVertexAttribArray(2);
	glVertexAttribDivisor(2, 1);
	glBindVertexArray(0);
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
	CHECK(glGetError() == GL_NO_ERROR);

	glEnable(GL_DEPTH_TEST);
	glEnable(GL_CULL_FACE);
}

/* Draws frame `frame` into the current surface of side `size`. */
static void draw(int frame, int size)
{
	/* Perspective: 45 degrees, near 1, far 30, aspect 1; the field is 14 away. */
	static const float PROJECTION[16] = {
		2.414213562f, 0, 0, 0,
		0, 2.414213562f, 0, 0,
		0, 0, -1.068965517f, -1,
		0, 0, -2.068965517f, 0};
	static const float VIEW[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, -14, 1};
	float sz = SIN_Z[frame], cz = COS_Z[frame];
	float rz[16] = {cz, sz, 0, 0, -sz, cz, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
	float rx[16] = {1, 0, 0, 0, 0, COS_X, SIN_X, 0, 0, -SIN_X, COS_X, 0, 0, 0, 0, 1};
	struct scene_block block;
	mat4_mul(block.model, rx, rz);
	mat4_mul(block.viewproj, PROJECTION, VIEW);
	static const float LIGHT[4] = {0.502519f, 0.703526f, 0.502519f, 0.0f};
	static const float PALETTE[4][4] = {
		{0.9f, 0.2f, 0.2f, 1}, {0.2f, 0.9f, 0.2f, 1}, {0.2f, 0.3f, 0.9f, 1}, {0.9f, 0.8f, 0.2f, 1}};
	memcpy(block.light, LIGHT, sizeof LIGHT);
	memcpy(block.palette, PALETTE, sizeof PALETTE);
	glBindBuffer(GL_UNIFORM_BUFFER, scene_buffer);
	glBufferSubData(GL_UNIFORM_BUFFER, 0, sizeof block, &block);
	glViewport(0, 0, size, size);
	glClearColor(0.10f, 0.15f, 0.20f, 1.0f);
	glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
	glBindVertexArray(vao);
	glDrawElementsInstanced(GL_TRIANGLES, index_count, GL_UNSIGNED_SHORT, (const void *)0, INSTANCES);
	glFinish();
	CHECK(glGetError() == GL_NO_ERROR);
}

/* The frame as glReadPixels gives it; its CRC-32 and byte sum. */
static void read_frame(uint8_t *pixels, int size, uint32_t *crc, uint64_t *sum)
{
	size_t length = (size_t)size * size * 4;
	memset(pixels, 0xA5, length);
	glReadPixels(0, 0, size, size, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
	CHECK(glGetError() == GL_NO_ERROR);
	*crc = crc_update(0xFFFFFFFFu, pixels, length) ^ 0xFFFFFFFFu;
	uint64_t total = 0;
	for (size_t i = 0; i < length; i++)
		total += pixels[i];
	*sum = total;
}

/* The CRC-32 of the points of a window's buffer as the host takes it from a
 * screenshot: red, green and blue of each point, rows from the top. */
static uint32_t window_crc(const struct stafeto_window *w, unsigned buffer)
{
	uint32_t crc = 0xFFFFFFFFu;
	for (uint32_t y = 0; y < w->height; y++) {
		const uint32_t *row = (const uint32_t *)((const uint8_t *)w->pixels[buffer] + (size_t)y * w->stride);
		for (uint32_t x = 0; x < w->width; x++) {
			uint8_t rgb[3] = {(uint8_t)(row[x] >> 16), (uint8_t)(row[x] >> 8), (uint8_t)row[x]};
			crc = crc_update(crc, rgb, 3);
		}
	}
	return ~crc;
}

int main(int argc, char **argv)
{
	int probe = 0, size = 160, frames = FRAMES_MAX, hold_fd = -1;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--probe") == 0) {
			probe = 1;
		} else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
			size = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--frames") == 0 && i + 1 < argc) {
			frames = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--hold") == 0 && i + 1 < argc) {
			hold_fd = atoi(argv[++i]);
		} else {
			printf("gles3-demo: unknown argument %s\n", argv[i]);
			return 2;
		}
	}
	if (!probe || size < 16 || size > SCREEN_H || frames < 1 || frames > FRAMES_MAX) {
		printf("usage: gles3-demo --probe [--size N] [--frames N] [--hold FD]\n");
		return 2;
	}
	crc_init();

	EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
	CHECK(display != EGL_NO_DISPLAY);
	EGLint major = 0, minor = 0;
	CHECK(eglInitialize(display, &major, &minor) == EGL_TRUE);
	printf("gles3-demo: EGL %d.%d %s\n", (int)major, (int)minor, eglQueryString(display, EGL_VENDOR));
	CHECK(eglBindAPI(EGL_OPENGL_ES_API) == EGL_TRUE);
	EGLConfig config = choose_config(display);
	static const EGLint context_attributes[] = {EGL_CONTEXT_MAJOR_VERSION, 3, EGL_CONTEXT_MINOR_VERSION, 0,
						    EGL_NONE};
	EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
	CHECK(context != EGL_NO_CONTEXT);

	/* Phase 1: the pbuffer, no window. */
	const EGLint pbuffer_attributes[] = {EGL_WIDTH, size, EGL_HEIGHT, size, EGL_NONE};
	EGLSurface pbuffer = eglCreatePbufferSurface(display, config, pbuffer_attributes);
	CHECK(pbuffer != EGL_NO_SURFACE);
	CHECK(eglMakeCurrent(display, pbuffer, pbuffer, context) == EGL_TRUE);
	print_string("GL_VENDOR", GL_VENDOR);
	print_string("GL_RENDERER", GL_RENDERER);
	print_string("GL_VERSION", GL_VERSION);
	setup();
	uint8_t *pixels = malloc((size_t)size * size * 4);
	CHECK(pixels != NULL);
	uint32_t pbuffer_crc[FRAMES_MAX];
	for (int frame = 0; frame < frames; frame++) {
		uint64_t sum;
		draw(frame, size);
		read_frame(pixels, size, &pbuffer_crc[frame], &sum);
		CHECK(sum != 0);
		printf("gles3-demo: frame %d crc %08x sum %llu\n", frame, (unsigned)pbuffer_crc[frame],
		       (unsigned long long)sum);
	}
	CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) == EGL_TRUE);
	CHECK(eglDestroySurface(display, pbuffer) == EGL_TRUE);

	/* Phase 2: a window of the composition service, the same frames. */
	struct stafeto_window window;
	int number = stafeto_window_open((SCREEN_W - size) / 2, (SCREEN_H - size) / 2, size, size,
					 STAFETO_WINDOW_XRGB8888, WINDOW_BUFFERS, 0, &window);
	CHECK(number == 0);
	EGLSurface surface = eglCreateWindowSurface(display, config, (EGLNativeWindowType)(number + 1), NULL);
	CHECK(surface != EGL_NO_SURFACE);
	CHECK(eglMakeCurrent(display, surface, surface, context) == EGL_TRUE);
	unsigned shown = 0;
	for (int frame = 0; frame < frames; frame++) {
		uint64_t sum;
		uint32_t crc;
		draw(frame, size);
		read_frame(pixels, size, &crc, &sum);
		CHECK(crc == pbuffer_crc[frame]);
		CHECK(eglSwapBuffers(display, surface) == EGL_TRUE);
		/* The buffer the swap filled is the one whose rows are the mirror of the
		 * readback; no other buffer holds this frame. */
		int found = 0;
		for (unsigned k = 0; k < window.buffers; k++) {
			if (swap_window_matches_readback((const unsigned char *)window.pixels[k], window.stride,
							 pixels, size, size)) {
				found++;
				shown = k;
			}
		}
		CHECK(found == 1);
		CHECK(!swap_readback_is_symmetric(pixels, size, size));
		printf("gles3-demo: window frame %d crc %08x matches the pbuffer, and the window holds its rows mirrored\n",
		       frame, (unsigned)crc);
	}
	uint32_t held = window_crc(&window, shown);
	printf("gles3-demo: held crc %08x\n", (unsigned)held);
	fflush(stdout);
	free(pixels);
	if (hold_fd >= 0) {
		char byte = 'h';
		CHECK(write(hold_fd, &byte, 1) == 1);
		for (;;) {
			struct timespec forever = {3600, 0};
			nanosleep(&forever, NULL);
		}
	}
	CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) == EGL_TRUE);
	CHECK(eglDestroySurface(display, surface) == EGL_TRUE);
	CHECK(eglDestroyContext(display, context) == EGL_TRUE);
	CHECK(eglTerminate(display) == EGL_TRUE);
	CHECK(stafeto_window_close(number) == 0);
	printf("gles3-demo: ok\n");
	return 0;
}
