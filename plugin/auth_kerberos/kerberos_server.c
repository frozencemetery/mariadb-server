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

  This is the server side implementation.
*/
#include <mysql/plugin_auth.h>

#include "kerberos_common.h"

#define KRB_SERVER_AUTH_ERROR 1

/* plugin global variables */
char *kerberos_principal_name; /* system-wise declaration for spn */
char *kerberos_keytab_path;
/**
 * underlying storage for Kerberos service principal name system variable
 */
static char kerberos_spn_storage[PRINCIPAL_NAME_LEN];
static char kerberos_ktpath_storage[PRINCIPAL_NAME_LEN]; /* TODO */

#ifdef _WIN32
static int sspi_kerberos_auth(MYSQL_PLUGIN_VIO *vio,
                              MYSQL_SERVER_AUTH_INFO *info)
{
  int read_len = 0;
  int max_token_sz = SSPI_MAX_TOKEN_SIZE;
  int ret = CR_OK; /* return code */
  const char *err_msg = NULL; /* error message */
  /* SSPI related fields */
  SECURITY_STATUS ss = 0;
  BOOL have_ctxt = FALSE;
  BOOL have_cred = FALSE;
  BOOL context_established = FALSE;
  ULONG attribs = 0;
  TimeStamp lifetime;

  CredHandle cred_handle; /* credential handle */
  CtxtHandle ctxt_handle; /* context handle */
  SecPkgContext_NativeNames native_names;

  SecPkgInfo *sec_pkg_info; /* Packet information */
  SecBufferDesc input_buf_desc; /* Input token */
  SecBuffer input_buf;
  SecBufferDesc output_buf_desc; /* Output token */
  SecBuffer output_buf;
  PBYTE output_con;

  /* query packet information */
  ss = QuerySecurityPackageInfo(SECURITY_PACKAGE_NAME, &sec_pkg_info);

  if (ss != SEC_E_OK)
  {
    /* error query package information */
    my_error(KRB_SERVER_AUTH_ERROR, MF_WARNING,
             "Kerberos: fail to get maximum token size, use default: %d.",
             max_token_sz);
  }
  else
  {
    max_token_sz = sec_pkg_info->cbMaxToken;
  }

  /* allocate memory */
  output_con = (PBYTE) calloc(max_token_sz, sizeof(BYTE));
  if (!output_con)
  {
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, "Kerberos: no more memory.");
    return CR_ERROR;
  }

  /* acquire initial credential */
  ss = AcquireCredentialsHandle(NULL, /* use default credential */
                                SECURITY_PACKAGE_NAME,
                                SECPKG_CRED_INBOUND, /* cred usage */
                                NULL, /* locally unique id */
                                NULL, /* use default credential */
                                NULL, /* get key func */
                                NULL, /* get key argument func */
                                &cred_handle, &lifetime);

  /* AcquireCredentialsHandle error checking */
  if (SEC_ERROR(ss))
  {
    err_msg = error_msg(ss);
    ret = CR_ERROR;
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, err_msg);
    goto cleanup;
  }
  else
  {
    have_cred = TRUE;
  }

  /* prepare input buffer */
  input_buf_desc.ulVersion = SECBUFFER_VERSION;
  input_buf_desc.cBuffers = 1;
  input_buf_desc.pBuffers = &input_buf;

  input_buf.cbBuffer = 0;
  input_buf.BufferType = SECBUFFER_TOKEN;
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
    /* read credential from client */
    read_len = vio->read_packet(vio, (unsigned char **) &input_buf.pvBuffer);
    if (read_len < 0)
    {
      ret = CR_ERROR;
      my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
               "Kerberos: fail read client credentials.");
      goto cleanup;
    }
    input_buf.cbBuffer = read_len;

    ss = AcceptSecurityContext(&cred_handle, /* credential */
                               have_ctxt ? &ctxt_handle : NULL,
                               &input_buf_desc, /* input credentials */
                               attribs, SECURITY_NATIVE_DREP,
                               &ctxt_handle, /* secure context */
                               &output_buf_desc, /* output credentials */
                               &attribs, &lifetime);

    /* AcceptSecurityContext error checking */
    if (SEC_ERROR(ss))
    {
      err_msg = error_msg(ss);
      ret = CR_ERROR;
      my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, err_msg);
      goto cleanup;
    }
    /* Security context established (partially) */
    have_ctxt = TRUE;

    if (output_buf.cbBuffer)
    {
      /* write credential packet */
      if (vio->write_packet(vio, (const unsigned char *) output_buf.pvBuffer,
                            output_buf.cbBuffer))
      {
        ret = CR_ERROR;
        my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
                 "Kerberos: fail send crednetials to client.");
        goto cleanup;
      }
    }
    output_buf.cbBuffer = max_token_sz;

    if ((ss == SEC_I_COMPLETE_NEEDED) || (ss == SEC_I_COMPLETE_AND_CONTINUE))
    {
      ss = CompleteAuthToken(&ctxt_handle, &output_buf_desc);
      if (SEC_ERROR(ss))
      {
        err_msg = error_msg(ss);
        ret = CR_ERROR;
        my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, err_msg);
        goto cleanup;
      }
    }

    context_established = !((ss == SEC_I_CONTINUE_NEEDED) ||
                            (ss == SEC_I_COMPLETE_AND_CONTINUE));
  } while (!context_established);

  /* check principal name */
  ss = QueryContextAttributes(&ctxt_handle, SECPKG_ATTR_NATIVE_NAMES,
                              &native_names);

  if (SEC_ERROR(ss))
  {
    err_msg = error_msg(ss);
    ret = CR_ERROR;
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, err_msg);
    goto cleanup;
  }

  if (strcmp(native_names.sClientName, info->auth_string))
  {
    ret = CR_ERROR;
  }
  else
  {
    ret = CR_OK;
  }

cleanup:
  /* free dynamic memory */
  if (have_ctxt)
    DeleteSecurityContext(&ctxt_handle);
  if (have_cred)
    FreeCredentialsHandle(&cred_handle);
  free(output_con);
  ss = FreeContextBuffer(sec_pkg_info);
  if (ss != SEC_E_OK)
  {
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
             "Kerberos: fail to free SecurityPackageInfo object.");
    /* return code is not modified */
  }

  return ret;
}
#else /* !_WIN32 */
static int gssapi_kerberos_auth(MYSQL_PLUGIN_VIO *vio,
                                MYSQL_SERVER_AUTH_INFO *info)
{
  int r_len = 0; /* packet read length */
  int rc = CR_OK; /* return code */
  int have_cred = FALSE;
  int have_ctxt = FALSE;
  const char *err_msg = NULL; /* error message text */
  /* GSSAPI related fields */
  OM_uint32 major = 0, minor = 0, flags = 0;
  gss_cred_id_t cred; /* credential identifier */
  gss_ctx_id_t ctxt; /* context identifier */
  gss_name_t client_name, service_name;
  gss_buffer_desc principal_name_buf, client_name_buf, input, output;

  /* import service principal from plain text */
  /* initialize principal name */
  principal_name_buf.length = strlen(kerberos_principal_name);
  principal_name_buf.value = kerberos_principal_name;
  major = gss_import_name(&minor, &principal_name_buf,
                          (gss_OID) gss_nt_user_name, &service_name);
  /* gss_import_name error checking */
  if (GSS_ERROR(major))
  {
    err_msg = error_msg(major, minor);
    rc = CR_ERROR;
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, err_msg);
    goto cleanup;
  }

  /* server acquires credential */
  if (kerberos_keytab_path[0] != '\0')
  {
    /* it's been set */
    gss_key_value_element_desc element = { "keytab", kerberos_keytab_path, };
    gss_key_value_set_desc cred_store = { 1, &element, };
    major = gss_acquire_cred_from(&minor, service_name, GSS_C_INDEFINITE,
                                 GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred_store,
                                 &cred, NULL, NULL);
  }
  else
  {
    /* if there's no keytab set, try to use the env var */
    major = gss_acquire_cred(&minor, service_name, GSS_C_INDEFINITE,
                             GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred, NULL,
                             NULL);    
  }

  /* gss_acquire_cred error checking */
  if (GSS_ERROR(major))
  {
    err_msg = error_msg(major, minor);
    rc = CR_ERROR;
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, err_msg);
    goto cleanup;
  }
  else
  {
    have_cred = TRUE;
  }

  major = gss_release_name(&minor, &service_name);
  if (major == GSS_S_BAD_NAME)
  {
    rc = CR_ERROR;
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, "Kerbeos: fail when invoke "
                                              "gss_release_name, no valid "
                                              "name found.");
    goto cleanup;
  }

  /* accept security context */
  ctxt = GSS_C_NO_CONTEXT;
  /* first trial */
  input.length = 0;
  input.value = NULL;
  do
  {
    /* receive token from peer first */
    r_len = vio->read_packet(vio, (unsigned char **) &input.value);
    if (r_len < 0)
    {
      rc = CR_ERROR;
      my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
               "Kerberos: fail to read token from client.");
      goto cleanup;
    }
    else
    {
      /* make length consistent with value */
      input.length = r_len;
    }

    major = gss_accept_sec_context(&minor, &ctxt, /* ctxt handle */
                                   cred, &input, /* input buffer */
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &client_name, /* source name */
                                   NULL, /* mech type */
                                   &output, /* output buffer */
                                   &flags, /* return flag */
                                   NULL, /* time rec */
                                   NULL);
    if (GSS_ERROR(major))
    {
      if (ctxt != GSS_C_NO_CONTEXT)
      {
        gss_delete_sec_context(&minor, &ctxt, GSS_C_NO_BUFFER);
      }
      err_msg = error_msg(major, minor);
      rc = CR_ERROR;
      my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR, err_msg);
      goto cleanup;
    }
    /* security context established (partially) */
    have_ctxt = TRUE;

    /* send token to peer */
    if (output.length)
    {
      if (vio->write_packet(vio, output.value, output.length))
      {
        gss_release_buffer(&minor, &output);
        rc = CR_ERROR;
        my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
                 "Kerberos: fail to send authentication token.");
        goto cleanup;
      }
      gss_release_buffer(&minor, &output);
    }
  } while (major & GSS_S_CONTINUE_NEEDED);

  /* extrac plain text client name */
  major = gss_display_name(&minor, client_name, &client_name_buf, NULL);
  if (major == GSS_S_BAD_NAME)
  {
    rc = CR_ERROR;
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
             "Kerberos: fail to display an ill-formed principal name.");
    goto cleanup;
  }

  /* expected user? */
  if (strncmp(client_name_buf.value, info->auth_string, PRINCIPAL_NAME_LEN))
  {
    gss_release_buffer(&minor, &client_name_buf);
    rc = CR_ERROR;
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
             "Kerberos: fail authentication user.");
    goto cleanup;
  }
  gss_release_buffer(&minor, &client_name_buf);

cleanup:
  if (have_ctxt)
    gss_delete_sec_context(&minor, &ctxt, GSS_C_NO_BUFFER);
  if (have_cred)
    gss_release_cred(&minor, &cred);

  return rc;
}
#endif /* _WIN32 */

/**
 * The main server function of the Kerberos plugin.
 */
static int kerberos_auth(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  size_t p_len = 0; /* length of principal name */
  int rc = CR_OK; /* return code */
  char *principal_name = NULL;

  /* server sends service principal name first. */
  p_len = strlen(kerberos_principal_name);
  if (!p_len)
  {
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
             "Kerberos: no principal name specified.");
    return CR_ERROR;
  }

  if (vio->write_packet(vio, (unsigned char *) kerberos_principal_name,
                        (int) p_len) < 0)
  {
    my_error(KRB_SERVER_AUTH_ERROR, MF_ERROR,
             "Kerberos: fail to send service principal name.");
    return CR_ERROR;
  }

  rc =
#ifdef _WIN32
      sspi_kerberos_auth(vio, info);
#else /* !_WIN32 */
      gssapi_kerberos_auth(vio, info);
#endif /* _WIN32 */

  free(principal_name);

  return rc;
}

#ifdef _WIN32
static BOOL GetLogonSID(PSID *ppsid)
{
  BOOL succ = FALSE;
  HANDLE token;
  DWORD index;
  DWORD length = 0;
  PTOKEN_GROUPS ptg = NULL;

  /* Verify the parameter passed in is not NULL. */
  if (ppsid == NULL)
    goto cleanup;

  /* Open a handle to the access token for the calling process. */
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    goto cleanup;

  /* Get required buffer size and allocate the TOKEN_GROUPS buffer. */
  if (!GetTokenInformation(token, /* handle to the access token */
                           TokenGroups, /* get information about the token's
                                           groups */
                           (LPVOID) ptg, /* pointer to TOKEN_GROUPS buffer */
                           0, /* size of buffer */
                           &length /* receives required buffer size */
                           ))
  {
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
      goto cleanup;

    ptg =
        (PTOKEN_GROUPS) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length);

    if (ptg == NULL)
      goto cleanup;
  }

  /* Get the token group information from the access token. */
  if (!GetTokenInformation(token, /* handle to the access token */
                           TokenGroups, /* get information about the token's
                                           groups */
                           (LPVOID) ptg, /* pointer to TOKEN_GROUPS buffer */
                           length, /* size of buffer */
                           &length /* receives required buffer size */
                           ))
  {
    goto cleanup;
  }

  /* Loop through the groups to find the logon SID. */
  for (index = 0; index < ptg->GroupCount; index++)
  {
    if ((ptg->Groups[index].Attributes & SE_GROUP_LOGON_ID) ==
        SE_GROUP_LOGON_ID)
    {
      /* Found the logon SID; make a copy of it. */
      length = GetLengthSid(ptg->Groups[index].Sid);
      *ppsid = (PSID) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length);
      if (*ppsid == NULL)
        goto cleanup;
      if (!CopySid(length, *ppsid, ptg->Groups[index].Sid))
      {
        HeapFree(GetProcessHeap(), 0, (LPVOID) *ppsid);
        goto cleanup;
      }
      break;
    }
  }
  succ = TRUE;

cleanup:
  /* Free the buffer for the token groups. */
  if (ptg != NULL)
    HeapFree(GetProcessHeap(), 0, (LPVOID) ptg);

  return succ;
}

static VOID FreeLogonSID(PSID *ppsid)
{
  HeapFree(GetProcessHeap(), 0, (LPVOID) *ppsid);
}

static BOOLEAN LogonAsNetworkService(void)
{
  SID sNetServ;
  PSID psLogon = NULL;
  DWORD szSid = sizeof(sNetServ);
  BOOLEAN bRetCode = FALSE;

  if (GetLogonSID(&psLogon) &&
      CreateWellKnownSid(WinNetworkServiceSid, NULL, &sNetServ, &szSid) &&
      EqualSid(psLogon, &sNetServ))
  {
    bRetCode = TRUE;
  }

  if (psLogon)
    FreeLogonSID(&psLogon);

  return bRetCode;
}

static int initialize_principal_name(void *unused)
{
  ULONG len = sizeof(kerberos_spn_storage);
  CHAR *computer_name = NULL;
  CHAR *domain_name = NULL;

  /* principal name has already been set */
  if (kerberos_principal_name && kerberos_principal_name[0])
    return 0;

  if (!GetUserNameEx(NameUserPrincipal, kerberos_spn_storage, &len))
  {
    switch (GetLastError())
    {
    case ERROR_NO_SUCH_DOMAIN:
      my_error(KRB_SERVER_AUTH_ERROR, MF_WARNING,
               "Kerberos: the domain controller is not up.");
      return CR_ERROR;
    case ERROR_NONE_MAPPED:
      /* cannot find UPN for logon user */
      /*
       * If logon sid is NetworkService, a fallback is construct
       * UPN (computer$@domain) manually.
       */
      if (LogonAsNetworkService())
      {
        len = PRINCIPAL_NAME_LEN;
        computer_name = (CHAR *) calloc(len, sizeof(CHAR));
        if (!computer_name ||
            !GetComputerNameEx(ComputerNameDnsHostname, computer_name, &len))
          goto nm_fail;

        len = PRINCIPAL_NAME_LEN;
        domain_name = (CHAR *) calloc(len, sizeof(CHAR));
        if (!domain_name ||
            !GetComputerNameEx(ComputerNameDnsDomain, domain_name, &len))
          goto nm_fail;

        sprintf_s(kerberos_spn_storage, sizeof(kerberos_spn_storage),
                  "%s$@%s", computer_name, domain_name);
        kerberos_principal_name = kerberos_spn_storage;
        free(computer_name);
        free(domain_name);
        break;

      nm_fail:
        if (computer_name) {
          if (domain_name)
            free(domain_name);
          free(computer_name);
        }
        my_error(-1, MF_ERROR,
                 "Kerberos: the name is not available in specific format.");
        return -1;
      }
      else
      {
        my_error(-1, MF_ERROR,
                 "Kerberos: the name is not available in specific format.");
        return -1;
      }
      break;
    default:
      break;
    }
  }
  else
  {
    /* redirect the variable */
    kerberos_principal_name = kerberos_spn_storage;
  }

  return 0;
}
#endif /* _WIN32 */

static int verify_principal_name(UNUSED(MYSQL_THD thd),
                                 UNUSED(struct st_mysql_sys_var UNUSED(*var)),
                                 UNUSED(void *save),
                                 struct st_mysql_value *value)
{
  char upn_buf[PRINCIPAL_NAME_LEN];
  int buf_len = PRINCIPAL_NAME_LEN;
  /* UPN should in the form `user@domain` or `user/host@domain` */
  const char *ptr = value->val_str(value, upn_buf, &buf_len);
  const char *itr = ptr;

#define FWD_ITER(iter)                                                       \
  while (*iter && (isalpha(*iter) || (*itr) == '.'))                         \
  iter++
  /* user part */
  if (*itr && isalpha(*itr))
  {
    FWD_ITER(itr);
  }
  else
  {
    /* name part is required */
    return 1;
  }

  /* host part, which is optional */
  if (*itr && *itr == '/')
  {
    itr++;
    FWD_ITER(itr);
  }

  /* domain part */
  if (*itr && *itr == '@')
  {
    itr++;
    FWD_ITER(itr);
  }
  else
  {
    /* domain part is required */
    return 1;
  }

  /* if validated return 0, or any non-zero value */
  if (!*itr)
  {
    strncpy(kerberos_spn_storage, ptr, PRINCIPAL_NAME_LEN);
  }
  return *itr;
}

static void update_principal_name(UNUSED(MYSQL_THD thd),
                                  UNUSED(struct st_mysql_sys_var *var),
                                  UNUSED(void *var_ptr),
                                  UNUSED(const void *save))
{
  kerberos_principal_name = kerberos_spn_storage;
}

static int verify_keytab_path(UNUSED(MYSQL_THD thd),
    UNUSED(struct st_mysql_sys_var UNUSED(*var)), UNUSED(void *save),
    struct st_mysql_value *value) {
  char path_buf[PRINCIPAL_NAME_LEN];
  int buf_len= PRINCIPAL_NAME_LEN;

  const char *ptr= value->val_str(value, path_buf, &buf_len);

  /* paths must be fully-qualified */
  if (ptr[0] == '/' && !access(ptr, R_OK))
  {
    strncpy(kerberos_ktpath_storage, ptr, PRINCIPAL_NAME_LEN);
    return 0;
  }
  return 1;
}

static void update_keytab_path(UNUSED(MYSQL_THD thd),
    UNUSED(struct st_mysql_sys_var* var), UNUSED(void * var_ptr),
    UNUSED(const void * save))
{
  kerberos_keytab_path= kerberos_ktpath_storage;
}

/* system variable */
static MYSQL_SYSVAR_STR(principal_name, kerberos_principal_name,
                        PLUGIN_VAR_RQCMDARG,
                        "Service principal name in Kerberos authentication.",
                        verify_principal_name, update_principal_name, "");
static MYSQL_SYSVAR_STR(keytab_path, kerberos_keytab_path,
                        PLUGIN_VAR_RQCMDARG,
                        "Location of Kerberos keytab.",
                        verify_keytab_path, update_keytab_path, "");

static struct st_mysql_sys_var *system_variables[] =
{
  MYSQL_SYSVAR(principal_name), MYSQL_SYSVAR(keytab_path), NULL,
};

/* register Kerberos authentication plugin */
static struct st_mysql_auth server_handler =
    {MYSQL_AUTHENTICATION_INTERFACE_VERSION, "kerberos_client",
     kerberos_auth};

maria_declare_plugin(kerberos_server)
{
  MYSQL_AUTHENTICATION_PLUGIN, &server_handler, "kerberos", "Shuang Qiu",
      "Plugin for Kerberos based authentication.", PLUGIN_LICENSE_GPL,
#ifdef _WIN32
      initialize_principal_name,
#else /* _WIN32 */
      NULL,
#endif /* _WIN32 */
      NULL, /* destructor */
      0x0100, /* version */
      NULL, /* status variables */
      system_variables, /* system variables */
      "Kerberos authentication plugin 1.0",
      MariaDB_PLUGIN_MATURITY_EXPERIMENTAL /* TODO change when release */
}
maria_declare_plugin_end;

/* localize macro KRB_AUTH_SERVER_ERROR */
#undef KRB_AUTH_SERVER_ERROR
