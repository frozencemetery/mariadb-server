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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
   */

/**
  @file

  Kerberos authentication utilities

  Utility functions are defined.
*/
#include "kerberos_common.h"

#ifdef _WIN32
/* translate status code to error message */
const char *error_msg(SECURITY_STATUS ss)
{
  const char *err_msg = NULL;

  switch (ss)
  {
  case SEC_E_INSUFFICIENT_MEMORY:
    err_msg = "Kerberos: insufficient memory to complete the request.";
    break;
  case SEC_E_INTERNAL_ERROR:
    err_msg = "Kerberos: an internal error occurs.";
    break;
  case SEC_E_NO_CREDENTIALS:
    err_msg = "Kerberos: no credentials are available.";
    break;
  case SEC_E_NOT_OWNER:
    err_msg = "Kerberos: necessary credentials to "
              "acquire the new credential are not found.";
    break;
  case SEC_E_UNKNOWN_CREDENTIALS:
    err_msg = "Kerberos: credentials supplied were not recognized.";
    break;
  case SEC_E_INVALID_HANDLE:
    err_msg = "Kerberos: an invalid handle is provided.";
    break;
  case SEC_E_INVALID_TOKEN:
    err_msg = "Kerberos: an invalid token is provided.";
    break;
  case SEC_E_LOGON_DENIED:
    err_msg = "Kerberos: logon as specified principal failed.";
    break;
  case SEC_E_NO_AUTHENTICATING_AUTHORITY:
    err_msg = "Kerberos: the domain name is invalid.";
    break;
  case SEC_E_TARGET_UNKNOWN:
    err_msg = "Kerberos: the target principal is unknown.";
    break;
  case SEC_E_WRONG_PRINCIPAL:
    err_msg = "Kerberos: the target principle does not "
              "match with expected one.";
    break;
  case SEC_E_TIME_SKEW:
    err_msg = "Kerberos: a time skew is detected.";
    break;
  default:
    err_msg = "Kerberos: unknown error.";
    break;
  }

  return err_msg;
}
#else /* _WIN32 */
#define ERR_MSG_BUF_LEN 1024
static char err_msg_buf[ERR_MSG_BUF_LEN];

const char *error_msg(OM_uint32 major,
                      OM_uint32 minor __attribute__((unused)))
{
  const char *err_msg = NULL;

  switch (major)
  {
  case GSS_S_BAD_NAMETYPE:
  case GSS_S_BAD_NAME:
    err_msg = "Kerberos: input name could not be recognied.";
    break;
  case GSS_S_BAD_MECH:
    err_msg = "Kerberos: a bad mechanism is requested.";
    break;
  case GSS_S_CREDENTIALS_EXPIRED:
    err_msg = "Kerberos: the credentials could not be acquired "
              "for expiration.";
    break;
  case GSS_S_NO_CRED:
    err_msg = "Kerberos: no credentials were found for the specified name.";
    break;
  case GSS_S_DEFECTIVE_TOKEN:
    err_msg = "Kerberos: consistency checks performed on "
              "the input token failed.";
    break;
  case GSS_S_DEFECTIVE_CREDENTIAL:
    err_msg = "Kerberos: consistency checks performed on "
              "the credential failed.";
    break;
  case GSS_S_BAD_BINDINGS:
    err_msg = "Kerberos: the input token contains "
              "different channel bindings as specified.";
    break;
  case GSS_S_NO_CONTEXT:
    err_msg = "Kerberos: the supplied context handle is invalid.";
    break;
  case GSS_S_BAD_SIG:
    err_msg = "Kerberos: input token contains an invalid MIC.";
    break;
  case GSS_S_OLD_TOKEN:
    err_msg = "Kerberos: input token is too old.";
    break;
  case GSS_S_DUPLICATE_TOKEN:
    err_msg = "Kerberos: input token is a duplicate of a token "
              "already processed.";
    break;
  case GSS_S_FAILURE:
    snprintf(err_msg_buf, ERR_MSG_BUF_LEN,
             "Kerberos: undefined Kerberos error. "
             "Make sure a valid ticket-grant-ticket is acquired "
             "and refer minor error code %d for details.",
             minor);
    err_msg = err_msg_buf;
    break;
  default:
    err_msg = "Kerberos: unknown error.";
    break;
  }

  return err_msg;
}
#endif /* _WIN32 */
