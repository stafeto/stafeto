<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> -->

# Licences of the dEQP build

VK-GL-CTS and the sources it fetches go into the test images of stafeto
(`cargo xtask deqp`) and never into a release: the programs `deqp-egl` and its
kin are not packages. `tools/build-deqp.py` writes the texts of the licences of
what it links to `target/deqp/NOTICES`, from the files of the fetched trees.

| Component | Version | Licence (SPDX) | Fetched by | In the program |
|---|---|---|---|---|
| VK-GL-CTS (the framework and the EGL, GLES2, GLES3 and GLES31 modules) | tag `opengl-es-cts-3.2.14.1`, commit `067e8832315e79817ede1c4863804e440f5d1c80` | Apache-2.0 | `git fetch` of the commit, hash compared | yes |
| zlib | 1.2.13 | Zlib | `external/fetch_sources.py` (SHA-256 in the script) | yes |
| libpng | 1.6.50 | libpng-2.0 | `external/fetch_sources.py` (SHA-256 in the script) | yes |
| glslang | `7881226269b1596feb604515743f528f02041375` | BSD-3-Clause AND BSD-2-Clause AND MIT AND Apache-2.0 AND GPL-3.0-or-later WITH Bison-exception-2.2 | `external/fetch_sources.py` (revision compared) | archive linked, objects only as referenced |
| SPIRV-Tools | `65b2ace21293057714b7fa1e87bd764d3dcef305` | Apache-2.0 | `external/fetch_sources.py` (revision compared) | archive linked, objects only as referenced |
| SPIRV-Headers | `babee77020ff82b571d723ce2c0262e2ec0ee3f1` | MIT | `external/fetch_sources.py` (revision compared) | headers |
| Amber | `83c140b6f67f45220956b1971e83a53588b4c426` | Apache-2.0 | `external/fetch_sources.py` | no (directory only) |
| jsoncpp | `9059f5cad030ba11d37818847443a53918c327b1` | MIT | `external/fetch_sources.py` | no (directory only) |
| Vulkan-Docs | `ac8223b312d40a6bc1733fb3490bdcdb5a389d50` | CC-BY-4.0 and Apache-2.0 (its `LICENSE.adoc`) | `external/fetch_sources.py` | no |
| Vulkan-Video-Samples | `v0.3.9` | Apache-2.0 | `external/fetch_sources.py` | no |
| video_generator | `426300e12a5cc5d4676807039a1be237a2b68187` | no licence file in the tree; never built | `external/fetch_sources.py` | no |
| renderdoc_app.h | v1.1 | MIT (header of the file) | `external/fetch_sources.py` (SHA-256 in the script) | header, unused |

The Vulkan Validation Layers are not fetched (`--include-vvl` off).

The platform of stafeto (`platform/`, `targets/`, `include/`) is MIT and takes
no code from the trees above; it is written against the interfaces of
`framework/platform` (`tcu::Platform`, `glu::Platform`, `eglu::Platform`).
Apache-2.0 is compatible with the GPL-3.0-or-later of the rest of the
repository; the GPL-3.0-or-later part of glslang's generated parser has the
Bison exception and the same terms.
