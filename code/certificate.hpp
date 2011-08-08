#ifndef _w32_cr_Certificate_hpp__
#define _w32_cr_Certificate_hpp__

// Copyright(c) Andre Caron, 2009-2011
//
// This document is covered by the an Open Source Initiative approved software
// license.  A copy of the license should have been provided alongside
// this software package (see "license.txt").  If not, the license is available
// online at "http://www.opensource.org/licenses/mit-license".

/* secure channel api. */
#ifndef SECURITY_WIN32
#   define SECURITY_WIN32
#endif
#include <WinSock2.h>
#include <WinCrypt.h>
#include <SChnlSp.h>
#include <Security.h>

namespace w32 { namespace cr {

    ::PCCERT_CONTEXT acquire ();

    void release ( ::PCCERT_CONTEXT object );

} }

#endif /* _w32_cr_Certificate_hpp__ */
