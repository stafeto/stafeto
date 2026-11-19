/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The handler of a failed LVGL assertion (ports/lvgl/lv_conf.h): the
 * program ends at once, so a probe sees it. */
#ifndef STAFETO_LV_ASSERT_HANDLER_H
#define STAFETO_LV_ASSERT_HANDLER_H

#include <stdlib.h>

#define LV_ASSERT_HANDLER abort();

#endif
