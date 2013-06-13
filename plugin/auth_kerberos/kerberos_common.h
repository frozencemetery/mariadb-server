/* Copyright (C) 2013 Shuang Qiu and Monty Program Ab

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

/**
  @file

  Kerberos authentication utilities

  Utility functions are declared.
*/
#ifndef KERBEROS_COMMON_H
#define KERBEROS_COMMON_H

#include <my_sys.h>
#include <my_global.h>
#include <mysql.h>
#include <mysql/plugin_auth_common.h>
#include <ctype.h>
#include <string.h>

/* global define directives */
#define PRINCIPAL_NAME_LEN     256         /* TODO need a reference */

#define MF_ERROR               MYF(0)
#define MF_WARNING             MYF(1)

/* platform dependent header */
#ifdef _WIN32
    /* on Windows platform, SSPI is used to perform the authentication */
    #include <windows.h>

    #define SECURITY_WIN32                 /* User-mode SSPI application */
    #include <Security.h>
    #include <SecExt.h>
    #include <sspi.h>
#else  /* !_WIN32 */
    /**
     * on other platform, make sure the Kerberos environment is pre-configured
     * GSSAPI is used for inter-operation purpose between Windows platform
     */
    #include <gssapi/gssapi.h>
    #include <gssapi/gssapi_generic.h>
    #include <gssapi/gssapi_krb5.h>
#endif /* _WIN32 */

/* platform dependent define directives */
#ifdef _WIN32
    #define UNUSED(x) __pragma(warning(suppress:4100)) x /* warns suppressor */
#else
    #define UNUSED(x) x __attribute__((unused))
#endif /* _WIN32 */

#ifdef _WIN32
    #define SECURITY_PACKAGE_NAME          "Kerberos"
    #define SSPI_MAX_TOKEN_SIZE            12000

    #define SEC_ERROR(ss)                  ((ss) < 0)

    /* translate SECURITY_STATUS to error text */
    const char *error_msg(SECURITY_STATUS);
#else  /* _WIN32 */
    /* translate symbolic error number to text error message */
    const char *error_msg(OM_uint32, OM_uint32);
#endif /* _WIN32 */

#endif /* KERBEROS_COMMON_H */
