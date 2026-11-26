<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> -->

# Licences of the graphics stack

What a program that draws with EGL and OpenGL ES links, and what the test
images carry. The licence texts travel with each build (`target/mesa/NOTICES`,
`target/libcxx` licence files, `target/deqp/NOTICES`); this page lists them.

| Component | Version | Licence (SPDX) | Where | In a release |
|---|---|---|---|---|
| Mesa (softpipe, EGL, OpenGL ES) | 26.3.1 | MIT, with Apache-2.0, BSL-1.0, BSD-2-Clause, BSD-3-Clause, HPND-sell-variant and public-domain files | `packages/mesa.toml`, `tools/build-mesa.py`, `target/mesa/NOTICES` | linked into programs (the package installs no file) |
| Platform of stafeto in Mesa | this repository | MIT | `ports/mesa/stafeto`, `ports/mesa/patches` | linked |
| libdrm | 2.4.133 | MIT | fetched by `tools/build-mesa.py`, SHA-256 checked | linked (the parts Mesa calls) |
| Khronos headers `egl.h`, `eglext.h`, `eglplatform.h`, `gl2platform.h`, `gl3platform.h` | as in Mesa 26.3.1 | Apache-2.0 | `target/mesa/include` | with the programs' sources |
| Khronos headers `gl2.h`, `gl3.h`, `gl2ext.h` and the other OpenGL ES headers | as in Mesa 26.3.1 | MIT | `target/mesa/include` | with the programs' sources |
| `KHR/khrplatform.h` | as in Mesa 26.3.1 | MIT-style text of its own header | `target/mesa/include` | with the programs' sources |
| OpenWF headers `WF/*.h` | 1.0 | Khronos permission notice (MIT-style, in each header) | `ports/openwf/include/WF` | with the programs' sources |
| libc++, libc++abi, libunwind (LLVM) | 23.1.6 | Apache-2.0 WITH LLVM-exception OR MIT OR NCSA | `packages/libcxx.toml`, `tools/build-libcxx.py` | linked into C++ programs and Mesa |
| VK-GL-CTS (dEQP) and the sources it fetches | `opengl-es-cts-3.2.14.1` | Apache-2.0 and the licences listed in `tests/deqp/LICENSES.md` | `tools/build-deqp.py`, `target/deqp/NOTICES` | no: test images only |

The graphics code of this repository (the window library, libWFC, libWFD, the
EGL platform, the dEQP platform) is MIT; the services (`compositor`,
`virtio-gpu`) are GPL-3.0-or-later like the other services. A closed program
that links the MIT parts and Mesa may stay closed.

The names of Khronos standards appear as names of interfaces. The words
"conformant" and "compatible" need the adopters program of Khronos and are not
used; the documents say that the interfaces are implemented and give the number
of cases that pass (`docs/deqp.md`).
