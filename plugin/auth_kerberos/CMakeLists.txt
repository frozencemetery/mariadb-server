IF (WIN32)
    # on Windows-platform, secur32.lib is certainly there.
    SET(KRB_LIB secur32)
ELSE (WIN32)
    # check include file
    CHECK_INCLUDE_FILES("gssapi/gssapi.h;gssapi/gssapi_generic.h;gssapi/gssapi_krb5.h" HAVE_GSSAPI_H)
    IF (NOT HAVE_GSSAPI_H)
        RETURN()
    ENDIF (NOT HAVE_GSSAPI_H)
    # on non-Windows-platform, check the existence of library gssapi_krb5.
    FIND_LIBRARY(KRB_LIB gssapi_krb5)
    IF (NOT KRB_LIB)
        # library is not there on the PATH.
        message("gssapi_krb5 not found.")
        RETURN()
    ENDIF (NOT KRB_LIB)
ENDIF (WIN32)

MYSQL_ADD_PLUGIN(kerberos kerberos_server.c kerberos_common.c
                 LINK_LIBRARIES ${KRB_LIB}
                 MODULE_ONLY COMPONENT SharedLibraries)
MYSQL_ADD_PLUGIN(kerberos_client kerberos_client.c kerberos_common.c
                 LINK_LIBRARIES ${KRB_LIB}
                 MODULE_ONLY COMPONENT SharedLibraries)
