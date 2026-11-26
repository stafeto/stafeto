// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#ifndef _TCUSTAFETOPLATFORM_HPP
#define _TCUSTAFETOPLATFORM_HPP

// The platform of stafeto for the test framework of VK-GL-CTS (dEQP): the
// EGL display of Mesa's platform of stafeto (EGL_DEFAULT_DISPLAY), windows
// of the composition service (<stafeto/window.h>) as the native windows of
// EGL, and the GLES contexts the framework makes on that display. Written
// against the interfaces of framework/platform in the tree of the CTS
// (tcu::Platform, glu::Platform, eglu::Platform); it takes no code from the
// platforms that tree holds.

#include "tcuDefs.hpp"
#include "tcuPlatform.hpp"
#include "gluPlatform.hpp"
#include "egluPlatform.hpp"

namespace tcu
{
namespace stafeto
{

class Platform : public tcu::Platform, private glu::Platform, private eglu::Platform
{
public:
    Platform();
    virtual ~Platform();

    virtual const glu::Platform &getGLPlatform() const
    {
        return static_cast<const glu::Platform &>(*this);
    }
    virtual const eglu::Platform &getEGLPlatform() const
    {
        return static_cast<const eglu::Platform &>(*this);
    }
};

} // namespace stafeto
} // namespace tcu

#endif // _TCUSTAFETOPLATFORM_HPP
