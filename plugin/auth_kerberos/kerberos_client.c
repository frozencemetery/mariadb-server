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

  Kerberos server authentication plugin

  kerberos_server is a general purpose server authentication plugin, it
  authenticates user against Kerberos principal.

  This is the client side implementation.
*/
#include <stdarg.h>
#include <mysqld_error.h>
#include <mysql/client_plugin.h>
#include "kerberos_common.h"

#define KERBEROS_UNKNOWN_ERROR "HY000"
#define KERBEROS_OUTOFMEMORY_ERROR "HY001"
#define KERBEROS_NET_ERROR_ON_WRITE "08S01"
#define KERBEROS_NET_READ_ERROR "08S01"

/**
 * set client error message
 */
static void set_krb_client_auth_error(MYSQL *, int, const char *,
                                      const char *);

#ifdef _WIN32
static int sspi_kerberos_auth_client(const char *spn, MYSQL *mysql,
                                     MYSQL_PLUGIN_VIO *vio)
{
  int read_len = 0;
  int max_token_sz = SSPI_MAX_TOKEN_SIZE;
  int ret = 0; /* return code */
  const char *err_msg = NULL;
  /* SSPI related */
  BOOL have_ctxt = FALSE;
  BOOL have_cred = FALSE;
  BOOL have_input = FALSE;
  BOOL context_established = FALSE;
  ULONG attribs = 0;
  TimeStamp lifetime;

  SECURITY_STATUS ss;
  CredHandle cred_handle; /* credential handle */
  CtxtHandle ctxt_handle; /* security context */

  SecPkgInfo *sec_pkg_info; /* package information */
  SecBufferDesc input_buf_desc;
  SecBuffer input_buf;
  SecBufferDesc output_buf_desc;
  SecBuffer output_buf;
  PBYTE output_con;

  /* query package information */
  ss = QuerySecurityPackageInfo(SECURITY_PACKAGE_NAME, &sec_pkg_info);
  if (ss == SEC_E_OK)
  {
    max_token_sz = sec_pkg_info->cbMaxToken;
  }

  /* allocate memory */
  output_con = (PBYTE) calloc(max_token_sz, sizeof(BYTE));
  if (!output_con)
  {
    set_krb_client_auth_error(
        mysql, ER_OUTOFMEMORY, KERBEROS_OUTOFMEMORY_ERROR,
        "Kerberos: insufficient memory to allocate for output token buffer.");
    return CR_ERROR;
  }

  /* acquire credentials */
  ss = AcquireCredentialsHandle(NULL, SECURITY_PACKAGE_NAME,
                                SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL,
                                &cred_handle, &lifetime);
  if (SEC_ERROR(ss))
  {
    err_msg = error_msg(ss);
    set_krb_client_auth_error(mysql, ER_UNKNOWN_ERROR, KERBEROS_UNKNOWN_ERROR,
                              err_msg);
    return CR_ERROR;
  }
  else
  {
    have_cred = TRUE;
  }

  /* prepare input buffer */
  input_buf_desc.ulVersion = SECBUFFER_VERSION;
  input_buf_desc.cBuffers = 1;
  input_buf_desc.pBuffers = &input_buf;
  input_buf.BufferType = SECBUFFER_TOKEN;
  input_buf.cbBuffer = 0;
  input_buf.pvBuffer = NULL;

  /* prepare output buffer */
  output_buf_desc.ulVersion = SECBUFFER_VERSION;
  output_buf_desc.cBuffers = 1;
  output_buf_desc.pBuffers = &output_buf;

  output_buf.BufferType = SECBUFFER_TOKEN;
  output_buf.cbBuffer = max_token_sz;
  output_buf.pvBuffer = output_con;

  do
  {
    ss = InitializeSecurityContext(&cred_handle, /* credential handle */
                                   have_ctxt ? &ctxt_handle
                                             : NULL, /* context handle */
                                   (SEC_CHAR *)
                                       spn, /* target principal name */
                                   0, /* no special attributes req-ed*/
                                   0, /* reserved */
                                   SECURITY_NATIVE_DREP,
                                   have_input ? &input_buf_desc : NULL,
                                   0, /* reserved */
                                   &ctxt_handle, &output_buf_desc, &attribs,
                                   &lifetime);
    /* reset used flag */
    have_input = FALSE;

    if (output_buf.cbBuffer)
    {
      /* send credential to server */
      if (vio->write_packet(vio, (const unsigned char *) output_buf.pvBuffer,
                            output_buf.cbBuffer))
      {
        ret = CR_ERROR;
        set_krb_client_auth_error(
            mysql, ER_NET_ERROR_ON_WRITE, KERBEROS_NET_ERROR_ON_WRITE,
            "Kerberos: fail send credentials to server.");
        goto cleanup;
      }
    }

    if (SEC_ERROR(ss))
    {
      err_msg = error_msg(ss);
      ret = CR_ERROR;
      set_krb_client_auth_error(mysql, ER_UNKNOWN_ERROR,
                                KERBEROS_UNKNOWN_ERROR, err_msg);
      goto cleanup;
    }

    have_ctxt = TRUE;

    if ((ss == SEC_I_COMPLETE_NEEDED) || (ss == SEC_I_COMPLETE_AND_CONTINUE))
    {
      ss = CompleteAuthToken(&ctxt_handle, &output_buf_desc);

      if (SEC_ERROR(ss))
      {
        err_msg = error_msg(ss);
        ret = CR_ERROR;
        set_krb_client_auth_error(mysql, ER_UNKNOWN_ERROR,
                                  KERBEROS_UNKNOWN_ERROR, err_msg);
        goto cleanup;
      }
    }

    context_established = !((ss == SEC_I_CONTINUE_NEEDED) ||
                            (ss == SEC_I_COMPLETE_AND_CONTINUE));
    if (!context_established)
    {
      read_len =
          vio->read_packet(vio, (unsigned char **) &input_buf.pvBuffer);
      if (read_len < 0)
      {
        ret = CR_ERROR;
        set_krb_client_auth_error(
            mysql, ER_NET_READ_ERROR, KERBEROS_NET_READ_ERROR,
            "Kerberos: fail to read credential from server.");
        goto cleanup;
      }
      else
      {
        input_buf.cbBuffer = read_len;
        have_input = TRUE;
      }
    }

    output_buf.cbBuffer = max_token_sz;
  } while (!context_established);

  ret = CR_OK;

cleanup:
  /* free dynamic memory */
  if (have_ctxt)
    DeleteSecurityContext(&ctxt_handle);
  free(output_con);
  ss = FreeContextBuffer(sec_pkg_info);
  if (ss != SEC_E_OK)
  {
    set_krb_client_auth_error(mysql, ER_UNKNOWN_ERROR, KERBEROS_UNKNOWN_ERROR,
                              "Kerberos: fail to free SecurityPackageInfo "
                              "object.");
  }

  return ret;
}
#else /* !_WIN32 */
static int gssapi_kerberos_auth_client(const char *spn, MYSQL *mysql,
                                       MYSQL_PLUGIN_VIO *vio)
{
  int r_len = 0; /* packet read length */
  int context_established = 0; /* indicate ctxt avail */
  int rc = CR_OK;
  int have_cred = FALSE;
  int have_ctxt = FALSE;
  int have_name = FALSE;
  const char *err_msg = NULL;
  /* GSSAPI related fields */
  OM_uint32 major = 0, minor = 0;
  gss_name_t service_name;
  gss_ctx_id_t ctxt;
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL; /* use default credential */
  gss_buffer_desc spn_buf, input, output;

  /* import principal from plain text */
  /* initialize plain text service principal name */
  spn_buf.length = strlen(spn);
  spn_buf.value = (void *) spn;
  /* import service principal */
  major = gss_import_name(&minor, &spn_buf, (gss_OID) gss_nt_user_name,
                          &service_name);
  /* gss_import_name error checking */
  if (GSS_ERROR(major))
  {
    err_msg = error_msg(major, minor);
    rc = CR_ERROR;
    set_krb_client_auth_error(mysql, ER_UNKNOWN_ERROR, KERBEROS_UNKNOWN_ERROR,
                              err_msg);
    goto cleanup;
  }
  have_name = TRUE;

  /* initial context */
  ctxt = GSS_C_NO_CONTEXT;
  input.length = 0;
  input.value = NULL;

  while (!context_established)
  {
    major = gss_init_sec_context(&minor, cred, &ctxt, service_name,
                                 GSS_C_NO_OID, /* for an impl-spec mech */
                                 0, /* no flags requested */
                                 0, /* request default time */
                                 GSS_C_NO_CHANNEL_BINDINGS,
                                 &input, /* token input */
                                 NULL, /* actual mech */
                                 &output, /* token output */
                                 NULL, /* actual flags */
                                 NULL); /* actual valid time */

    if (output.length)
    {
      /* send credential */
      if (vio->write_packet(vio, output.value, output.length))
      {
        gss_release_buffer(&minor, &output);
        rc = CR_ERROR;
        set_krb_client_auth_error(
            mysql, ER_NET_ERROR_ON_WRITE, KERBEROS_NET_ERROR_ON_WRITE,
            "Kerberos: fail to send credential to server.");
        goto cleanup;
      }
      gss_release_buffer(&minor, &output);
    }

    if (GSS_ERROR(major))
    {
      /* fatal error */
      if (ctxt != GSS_C_NO_CONTEXT)
      {
        gss_delete_sec_context(&minor, &ctxt, GSS_C_NO_BUFFER);
      }
      err_msg = error_msg(major, minor);
      rc = CR_ERROR;
      set_krb_client_auth_error(mysql, ER_UNKNOWN_ERROR,
                                KERBEROS_UNKNOWN_ERROR, err_msg);
      goto cleanup;
    }

    if (major & GSS_S_CONTINUE_NEEDED)
    {
      r_len = vio->read_packet(vio, (unsigned char **) &input.value);
      if (r_len < 0)
      {
        rc = CR_ERROR;
        set_krb_client_auth_error(
            mysql, ER_NET_READ_ERROR, KERBEROS_NET_READ_ERROR,
            "Error read credential packet from server.");
        goto cleanup;
      }
    }
    else
    {
      context_established = 1;
    }
  }

cleanup:
  if (have_name)
    gss_release_name(&minor, &service_name);
  if (have_ctxt)
    gss_delete_sec_context(&minor, &ctxt, GSS_C_NO_BUFFER);
  if (have_cred)
    gss_release_cred(&minor, &cred);

  return rc;
}
#endif /* _WIN32 */

/**
 * The main client function of the Kerberos plugin.
 */
static int kerberos_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  int r_len = 0;
  int rc = CR_OK;
  /* service principal name */
  char *spn = NULL;
  char *spn_buff = (char *) malloc(PRINCIPAL_NAME_LEN);

  /* read from server for service principal name */
  r_len = vio->read_packet(vio, (unsigned char **) &spn);
  if (r_len < 0)
  {
    set_krb_client_auth_error(
        mysql, ER_NET_READ_ERROR, KERBEROS_NET_READ_ERROR,
        "Kerberos: fail to read service principal name.");

    return CR_ERROR;
  }
  strncpy(spn_buff, spn, PRINCIPAL_NAME_LEN);

  rc =
#ifdef _WIN32
      sspi_kerberos_auth_client((const char *) spn_buff, mysql, vio);
#else /* !_WIN32 */
      gssapi_kerberos_auth_client((const char *) spn_buff, mysql, vio);
#endif /* _WIN32 */

  free(spn_buff);
  return rc;
}

/**
 * set client error message.
 * Param:
 *  mysql    connection handle
 *  errno    extended error number
 *  errmsg   error message
 */
static void set_krb_client_auth_error(MYSQL *mysql, int errcode,
                                      const char *sqlstate,
                                      const char *errmsg)
{
  NET *net = &mysql->net;
  va_list args;

  net->last_errno = errcode;
  strncpy(net->last_error, errmsg, sizeof(net->last_error) - 1);
  memcpy(net->sqlstate, sqlstate, sizeof(net->sqlstate));
}

/* register client plugin */
mysql_declare_client_plugin(AUTHENTICATION) "kerberos_client", "Shuang Qiu",
    "Kerberos based authentication", {0, 1, 0}, "GPL", NULL, NULL, NULL, NULL,
    kerberos_auth_client mysql_end_client_plugin;
