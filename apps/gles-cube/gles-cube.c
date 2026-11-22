/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The cube of stafeto: a C program on EGL 1.5 and OpenGL ES 2.0 (<EGL/egl.h>,
 * <GLES2/gl2.h>), which Mesa's softpipe driver runs on the processor.
 *
 * `gles-cube --pbuffer` draws a lit cube into a pbuffer surface, the surface of
 * EGL that has no window and needs no compositor, and reads each of ten frames
 * back with glReadPixels. For every frame it prints the CRC-32 (the one of
 * zlib: polynomial 0xEDB88320, initial value and final xor 0xFFFFFFFF) and the
 * sum of the bytes of the 160 x 160 RGBA image, rows from the bottom up as GL
 * returns them. The angles of the ten frames are tables in the program, so the
 * picture does not depend on the math library of the system: the same file
 * builds on Linux (cc gles-cube.c -lEGL -lGLESv2) against the same Mesa, and
 * the lines it prints there are the reference of the lines it prints here
 * (tools/mesa-reference).
 *
 * Options: --size N (the side of the square, default 160), --frames N (1 to
 * 10, default 10), --ascii N (print frame N, counted from 0, as 32 lines of 64
 * characters by brightness). The program asks for the software path of Mesa itself
 * (LIBGL_ALWAYS_SOFTWARE=1) and exits with 0 after the line "gles-cube: ok".
 * Built with -fno-builtin; every result is compared.
 */

#define _POSIX_C_SOURCE 200809L

#include <EGL/egl.h>
#include <GLES2/gl2.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FRAMES_MAX 10

/* Sine and cosine of the angles of the frames, about Y (0, 36, ... 324
 * degrees) and about X (20, 27, ... 83 degrees). */
static const float SIN_Y[FRAMES_MAX] = {
	0.000000000f, 0.587785252f, 0.951056516f, 0.951056516f, 0.587785252f,
	0.000000000f, -0.587785252f, -0.951056516f, -0.951056516f, -0.587785252f};
static const float COS_Y[FRAMES_MAX] = {
	1.000000000f, 0.809016994f, 0.309016994f, -0.309016994f, -0.809016994f,
	-1.000000000f, -0.809016994f, -0.309016994f, 0.309016994f, 0.809016994f};
static const float SIN_X[FRAMES_MAX] = {
	0.342020143f, 0.453990500f, 0.559192903f, 0.656059029f, 0.743144825f,
	0.819152044f, 0.882947593f, 0.933580426f, 0.970295726f, 0.992546152f};
static const float COS_X[FRAMES_MAX] = {
	0.939692621f, 0.891006524f, 0.829037573f, 0.754709580f, 0.669130606f,
	0.573576436f, 0.469471563f, 0.358367950f, 0.241921896f, 0.121869343f};

/* The vertex shader: position by the model-view-projection matrix, the normal
 * by the rotation of the model, a colour for each face. */
static const char VERTEX_SHADER[] =
	"uniform mat4 mvp;\n"
	"uniform mat3 rot;\n"
	"attribute vec3 position;\n"
	"attribute vec3 normal;\n"
	"attribute vec3 colour;\n"
	"varying vec3 v_normal;\n"
	"varying vec3 v_colour;\n"
	"void main() {\n"
	"  gl_Position = mvp * vec4(position, 1.0);\n"
	"  v_normal = rot * normal;\n"
	"  v_colour = colour;\n"
	"}\n";

/* The fragment shader: a directional light and an ambient term. */
static const char FRAGMENT_SHADER[] =
	"precision mediump float;\n"
	"varying vec3 v_normal;\n"
	"varying vec3 v_colour;\n"
	"void main() {\n"
	"  vec3 light = vec3(0.502519, 0.703526, 0.502519);\n"
	"  float d = max(dot(normalize(v_normal), light), 0.0);\n"
	"  gl_FragColor = vec4(v_colour * (0.25 + 0.75 * d), 1.0);\n"
	"}\n";

/* Six faces of four vertices: position, normal, colour. */
static const float CUBE[24 * 9] = {
	/* +X */
	1, -1, -1, 1, 0, 0, 0.9f, 0.2f, 0.2f,
	1, 1, -1, 1, 0, 0, 0.9f, 0.2f, 0.2f,
	1, 1, 1, 1, 0, 0, 0.9f, 0.2f, 0.2f,
	1, -1, 1, 1, 0, 0, 0.9f, 0.2f, 0.2f,
	/* -X */
	-1, -1, 1, -1, 0, 0, 0.2f, 0.8f, 0.8f,
	-1, 1, 1, -1, 0, 0, 0.2f, 0.8f, 0.8f,
	-1, 1, -1, -1, 0, 0, 0.2f, 0.8f, 0.8f,
	-1, -1, -1, -1, 0, 0, 0.2f, 0.8f, 0.8f,
	/* +Y */
	-1, 1, -1, 0, 1, 0, 0.2f, 0.9f, 0.2f,
	-1, 1, 1, 0, 1, 0, 0.2f, 0.9f, 0.2f,
	1, 1, 1, 0, 1, 0, 0.2f, 0.9f, 0.2f,
	1, 1, -1, 0, 1, 0, 0.2f, 0.9f, 0.2f,
	/* -Y */
	-1, -1, 1, 0, -1, 0, 0.8f, 0.2f, 0.8f,
	-1, -1, -1, 0, -1, 0, 0.8f, 0.2f, 0.8f,
	1, -1, -1, 0, -1, 0, 0.8f, 0.2f, 0.8f,
	1, -1, 1, 0, -1, 0, 0.8f, 0.2f, 0.8f,
	/* +Z */
	-1, -1, 1, 0, 0, 1, 0.2f, 0.3f, 0.9f,
	1, -1, 1, 0, 0, 1, 0.2f, 0.3f, 0.9f,
	1, 1, 1, 0, 0, 1, 0.2f, 0.3f, 0.9f,
	-1, 1, 1, 0, 0, 1, 0.2f, 0.3f, 0.9f,
	/* -Z */
	1, -1, -1, 0, 0, -1, 0.9f, 0.8f, 0.2f,
	-1, -1, -1, 0, 0, -1, 0.9f, 0.8f, 0.2f,
	-1, 1, -1, 0, 0, -1, 0.9f, 0.8f, 0.2f,
	1, 1, -1, 0, 0, -1, 0.9f, 0.8f, 0.2f,
};

static uint16_t indices[36];

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			printf("gles-cube: check failed at line %d: %s (egl 0x%x gl 0x%x)\n", __LINE__, #cond, \
			       (unsigned)eglGetError(), (unsigned)glGetError()); \
			exit(1); \
		} \
	} while (0)

static uint32_t crc_table[256];

/* Milliseconds of the monotonic clock. */
static long long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void crc_init(void)
{
	for (uint32_t n = 0; n < 256; n++) {
		uint32_t c = n;
		for (int k = 0; k < 8; k++)
			c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
		crc_table[n] = c;
	}
}

static uint32_t crc32_of(const uint8_t *data, size_t length)
{
	uint32_t c = 0xFFFFFFFFu;
	for (size_t i = 0; i < length; i++)
		c = crc_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
	return c ^ 0xFFFFFFFFu;
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
		printf("gles-cube: shader did not compile: %s\n", log);
		exit(1);
	}
	return shader;
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

/* The frame as 32 lines of 64 characters: the mean brightness of each block of
 * pixels, rows from the top. */
static void print_ascii(const uint8_t *pixels, int size)
{
	static const char RAMP[] = " .:-=+*#%@";
	for (int row = 0; row < 32; row++) {
		char line[65];
		for (int col = 0; col < 64; col++) {
			int x0 = col * size / 64, x1 = (col + 1) * size / 64;
			int y0 = (31 - row) * size / 32, y1 = (32 - row) * size / 32;
			unsigned long total = 0, count = 0;
			for (int y = y0; y < y1; y++)
				for (int x = x0; x < x1; x++) {
					const uint8_t *p = pixels + ((size_t)y * size + x) * 4;
					total += (p[0] + p[1] + p[2]) / 3;
					count++;
				}
			line[col] = RAMP[count ? total * 9 / (count * 255) : 0];
		}
		line[64] = 0;
		printf("gles-cube: ascii %s\n", line);
	}
}

static void print_string(const char *label, GLenum name)
{
	const GLubyte *text = glGetString(name);
	printf("gles-cube: %s %s\n", label, text ? (const char *)text : "(none)");
}

int main(int argc, char **argv)
{
	int size = 160;
	int frames = FRAMES_MAX;
	int pbuffer = 0;
	int ascii = -1;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--pbuffer") == 0) {
			pbuffer = 1;
		} else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
			size = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--frames") == 0 && i + 1 < argc) {
			frames = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--ascii") == 0 && i + 1 < argc) {
			ascii = atoi(argv[++i]);
		} else {
			printf("gles-cube: unknown argument %s\n", argv[i]);
			return 2;
		}
	}
	if (!pbuffer || size < 16 || size > 1024 || frames < 1 || frames > FRAMES_MAX) {
		printf("usage: gles-cube --pbuffer [--size N] [--frames N]\n");
		return 2;
	}
	for (int face = 0; face < 6; face++) {
		static const uint16_t quad[6] = {0, 1, 2, 0, 2, 3};
		for (int k = 0; k < 6; k++)
			indices[face * 6 + k] = (uint16_t)(face * 4 + quad[k]);
	}
	crc_init();

	/* The software path of Mesa: there is no device to find. */
	setenv("LIBGL_ALWAYS_SOFTWARE", "1", 1);
	EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
	CHECK(display != EGL_NO_DISPLAY);
	EGLint major = 0, minor = 0;
	CHECK(eglInitialize(display, &major, &minor) == EGL_TRUE);
	printf("gles-cube: EGL %d.%d %s\n", (int)major, (int)minor, eglQueryString(display, EGL_VENDOR));
	CHECK(eglBindAPI(EGL_OPENGL_ES_API) == EGL_TRUE);

	static const EGLint config_attributes[] = {
		EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
		EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
		EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
		EGL_DEPTH_SIZE, 16,
		EGL_NONE};
	EGLConfig config;
	EGLint configs = 0;
	CHECK(eglChooseConfig(display, config_attributes, &config, 1, &configs) == EGL_TRUE);
	CHECK(configs == 1);
	const EGLint surface_attributes[] = {EGL_WIDTH, size, EGL_HEIGHT, size, EGL_NONE};
	EGLSurface surface = eglCreatePbufferSurface(display, config, surface_attributes);
	CHECK(surface != EGL_NO_SURFACE);
	static const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
	EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
	CHECK(context != EGL_NO_CONTEXT);
	CHECK(eglMakeCurrent(display, surface, surface, context) == EGL_TRUE);
	print_string("GL_VENDOR", GL_VENDOR);
	print_string("GL_RENDERER", GL_RENDERER);
	print_string("GL_VERSION", GL_VERSION);

	long long compiled = now_ms();
	GLuint program = glCreateProgram();
	glAttachShader(program, compile(GL_VERTEX_SHADER, VERTEX_SHADER));
	glAttachShader(program, compile(GL_FRAGMENT_SHADER, FRAGMENT_SHADER));
	glBindAttribLocation(program, 0, "position");
	glBindAttribLocation(program, 1, "normal");
	glBindAttribLocation(program, 2, "colour");
	glLinkProgram(program);
	GLint linked = 0;
	glGetProgramiv(program, GL_LINK_STATUS, &linked);
	CHECK(linked);
	glUseProgram(program);
	printf("gles-cube: time shaders %lld ms\n", now_ms() - compiled);
	GLint mvp_at = glGetUniformLocation(program, "mvp");
	GLint rot_at = glGetUniformLocation(program, "rot");
	CHECK(mvp_at >= 0 && rot_at >= 0);

	GLuint buffers[2];
	glGenBuffers(2, buffers);
	glBindBuffer(GL_ARRAY_BUFFER, buffers[0]);
	glBufferData(GL_ARRAY_BUFFER, sizeof CUBE, CUBE, GL_STATIC_DRAW);
	glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, buffers[1]);
	glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof indices, indices, GL_STATIC_DRAW);
	glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 9 * sizeof(float), (const void *)0);
	glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, 9 * sizeof(float), (const void *)(3 * sizeof(float)));
	glVertexAttribPointer(2, 3, GL_FLOAT, GL_FALSE, 9 * sizeof(float), (const void *)(6 * sizeof(float)));
	glEnableVertexAttribArray(0);
	glEnableVertexAttribArray(1);
	glEnableVertexAttribArray(2);
	glEnable(GL_DEPTH_TEST);
	glEnable(GL_CULL_FACE);
	glViewport(0, 0, size, size);
	CHECK(glGetError() == GL_NO_ERROR);

	uint8_t *pixels = malloc((size_t)size * size * 4);
	CHECK(pixels != NULL);
	/* Perspective: 45 degrees, near 1, far 10, aspect 1. */
	static const float PROJECTION[16] = {
		2.414213562f, 0, 0, 0,
		0, 2.414213562f, 0, 0,
		0, 0, -1.222222222f, -1,
		0, 0, -2.222222222f, 0};
	for (int frame = 0; frame < frames; frame++) {
		long long started = now_ms();
		float sy = SIN_Y[frame], cy = COS_Y[frame], sx = SIN_X[frame], cx = COS_X[frame];
		/* model = Rx * Ry, then the view moves the cube 4 units away. */
		float ry[16] = {cy, 0, -sy, 0, 0, 1, 0, 0, sy, 0, cy, 0, 0, 0, 0, 1};
		float rx[16] = {1, 0, 0, 0, 0, cx, sx, 0, 0, -sx, cx, 0, 0, 0, 0, 1};
		float model[16], view[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, -4, 1};
		float modelview[16], mvp[16];
		mat4_mul(model, rx, ry);
		mat4_mul(modelview, view, model);
		mat4_mul(mvp, PROJECTION, modelview);
		float rot[9] = {model[0], model[1], model[2], model[4], model[5], model[6],
				model[8], model[9], model[10]};
		glUniformMatrix4fv(mvp_at, 1, GL_FALSE, mvp);
		glUniformMatrix3fv(rot_at, 1, GL_FALSE, rot);
		glClearColor(0.10f, 0.15f, 0.20f, 1.0f);
		glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
		glDrawElements(GL_TRIANGLES, 36, GL_UNSIGNED_SHORT, (const void *)0);
		glFinish();
		CHECK(glGetError() == GL_NO_ERROR);
		memset(pixels, 0xA5, (size_t)size * size * 4);
		glReadPixels(0, 0, size, size, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
		CHECK(glGetError() == GL_NO_ERROR);
		uint64_t sum = 0;
		for (size_t i = 0; i < (size_t)size * size * 4; i++)
			sum += pixels[i];
		printf("gles-cube: frame %d crc %08x sum %llu\n", frame, (unsigned)crc32_of(pixels, (size_t)size * size * 4),
		       (unsigned long long)sum);
		printf("gles-cube: time frame %d %lld ms\n", frame, now_ms() - started);
		if (frame == ascii)
			print_ascii(pixels, size);
	}
	free(pixels);
	CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) == EGL_TRUE);
	CHECK(eglDestroyContext(display, context) == EGL_TRUE);
	CHECK(eglDestroySurface(display, surface) == EGL_TRUE);
	CHECK(eglTerminate(display) == EGL_TRUE);
	printf("gles-cube: ok\n");
	return 0;
}
