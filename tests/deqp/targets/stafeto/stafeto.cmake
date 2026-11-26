# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#
# The target of stafeto for VK-GL-CTS: tools/build-deqp.py copies this file
# to targets/stafeto/ of the tree and the sources of tests/deqp/platform to
# framework/platform/stafeto/, and runs CMake with DEQP_TARGET=stafeto,
# GLES_ALLOW_DIRECT_LINK=ON and STAFETO_MESA_DIR set to target/mesa. The
# entry points of EGL and OpenGL ES are linked from Mesa's one archive (the
# framework has no dlopen to open libEGL.so with), so the three library
# variables name that archive and the headers are the ones of Khronos that
# the Mesa build copies.

message("*** Using stafeto target")
set(DEQP_TARGET_NAME "stafeto")

if (NOT STAFETO_MESA_DIR)
	message(FATAL_ERROR "STAFETO_MESA_DIR is not set (the build of Mesa: cargo xtask mesa)")
endif ()

set(STAFETO_MESA_LIBRARY ${STAFETO_MESA_DIR}/lib/libmesa.a)
include_directories(BEFORE ${STAFETO_MESA_DIR}/include)
# <stafeto/window.h>
include_directories(${STAFETO_WINDOW_INCLUDE})

set(DEQP_SUPPORT_GLES2   ON)
set(DEQP_SUPPORT_GLES3   ON)
set(DEQP_SUPPORT_GLES31  ON)
set(DEQP_SUPPORT_GLES32  OFF)
set(DEQP_SUPPORT_EGL     ON)

# Mesa's softpipe is GLES 3.1 (3.2 is not offered); one archive holds EGL
# and the entry points of every version.
set(DEQP_GLES2_LIBRARIES  ${STAFETO_MESA_LIBRARY})
set(DEQP_GLES3_LIBRARIES  ${STAFETO_MESA_LIBRARY})
set(DEQP_GLES31_LIBRARIES ${STAFETO_MESA_LIBRARY})
set(DEQP_EGL_LIBRARIES    ${STAFETO_MESA_LIBRARY})

set(TCUTIL_PLATFORM_SRCS
	stafeto/tcuStafetoMain.cpp
	stafeto/tcuStafetoPlatform.cpp
	stafeto/tcuStafetoPlatform.hpp
)
