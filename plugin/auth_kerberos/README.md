## Kerberos Authentication Plugin for MariaDB

This article gives instructions on configuring Kerberos authentication
plugin for MariaDB.  With Kerberos authentication plugin enabled, you can
login MariaDB as a Kerberos domain user passwordlessly.

### System Settings

To use the full feature of Kerberos authentication plugin, make sure a
Kerberos authentication domain is properly set up.

* For a pure *nix Kerberos domain, an [MIT Kerberos Key Distribution Centre][1]
(krb5kdc service) should be running.

* As to a pure Windows domain, an active directory domain controller should
be connectable.

* Hybrid Kerberos domains are also allowed.

Detailed guides to set up a Kerberos authentication domain is beyond the scope
of this document.  You can refer to the links in the References section on
how to setup a Kerberos authentication domain.

### Compile

The compilation of Kerberos authentication plugin has been integrated into
the CMake building framework of MariaDB.

##### *nix

If you are a *nix user, guarantee the Kerberos libraries and headers are
installed.

##### Windows

The Windows version requires no additional libraries.

The Kerberos authentication plugin is separated into two isolated parts:
the server-side plugin and client-side plugin.  If no errors occur
during compilation, two shared libraries will be created, `kerberos` and
`kerberos_client` for server-side and client-side plugin respectively.

### Installation

Install the server-side Kerberos authentication plugin before used.
Client-side plugin will be automatically loaded when required.

Connect MariaDB server as a superuser, then issue the command

    INSTALL PLUGIN kerberos SONAME 'kerberos';

This will instruct MariaDB server to load the Kerberos authentication plugin.

### Set a Service Principal Name to MariaDB

Before we can authenticate against Kerberos service, the last step is assign
a service principal name to MariaDB server.

#### Figure out a Valid Principal Name

Services and users are identified via principal names internally in Kerberos
authentication service.  Generally, a principal name is in the format of
`username/hostname@DOMAIN.NAME`.

##### *nix

For Kerberos services on *nix platform, a user specified service principal
name is required, since no default principal name can be derived from the
effective user of the server process.

##### Windows

As to Windows Active Directory services

* if MariaDB is running as `NetworkService` by default, the principal name
is akin `host$@DOMAIN.NAME`.  In this case, no need to specify service
principal name manually.  The Kerberos plugin can derive a valid default
service principal name.

* Otherwise, if you run MariaDB as a customized domain user, the principal
name is `username@DOMAIN.NAME` by default.  In this case, no need to specify
service principal name manually.  The Kerberos plugin can derive a valid
default service principal name.

* Finally, if a principal name is preferred over the default `username@DOMAIN`,
feel free to update it with the `setspn.exe` tool.  Correspondingly, the
new principal name must be specified in the MariaDB configuration file to
have it work.

A valid Kerberos principal name is case sensitive in both *nix and Windows.
For example, on *nix platform a valid service principal name is like
`MySQL/localhost@EXAMPLE.COM` (capitalised realm name is recommended by
Kerberos service) or `MySQL@EXAMPLE.COM` on Windows (`hostname` is not
emphasised).

#### Assign the Principal Name

To assign a service principal name to server, Kerberos authentication plugin
exposes a system variable `named kerberos_principal_name`.

One can specify the name (say, `MySQL/localhost@EXAMPLE.COM`) in three ways:

* Specify the name in configure file: edit local configure file ~/.my.cnf by
inserting the line `kerberos_principal_name=MySQL/localhost@EXAMPLE.COM` in the
server section.  * Pass as command line parameter: start MariaDB server with
command line parameter `--kerberos_principal_name=MySQL/localhost@EXAMPLE.COM`.
* If you can login MariaDB as a superuser, you can set by the following
commands: `SET GLOBAL kerberos_principal_name='MySQL/localhost@EXAMPLE.COM';`
The parameter should be set each time after the service restarts.

You can verify service principal name is properly set by

    SELECT @@global.kerberos_principal_name;

#### Create New MariaDB Users

If all the steps above are completed, you can now create a new user identified
via Kerberos authentication plugin.

    CREATE USER user_name IDENTIFIED VIA kerberos AS 'user_principal_name';

We need the `AS` clause to specify the principal name instead of embedded
into `user_name` directly for the length gap between MariaDB username and
Kerberos principal name.

#### Connect and Login as Kerboers Principal

To connect to MariaDB as `user_name`, first check a valid Kerberos tgt ticket
is cached with `klist`.  You can obtain a tgt ticket either by login as a
domain user on Windows platform or by `kinit principal_name` on Linux box.

If all these steps are done, you should now connect to MariaDB as `user_name`
successfully.

### Run Test Suite

This section describes how to run unit test for Kerberos authentication plugin.
In case of setting up a Kerberos domain, which is tedious to an ordinary user,
the unit test for Kerberos authentication plugin is by default skipped.

To run the unit test, an OS environment variable `MTR_KERBEROS_ENABLED`
should be set to a valid value

    MTR_KERBEROS_ENABLED=1

Two more OS environment variables `MTR_KERBEROS_SPN` and `MTR_KERBEROS_UPN`
should be set for MariaDB service principal name and login user principal
name respectively.

#### Extending the Ticket Lifetime

Make sure the tgt ticket is not expired for login user when running the
unit test.  In case early expiration of the ticket, we can extend the ticket
lifetime in configuration.

##### *nix

You can extend the ticket lifetime by editing `/etc/krb5.conf` in *nix by
updating two parameter `ticket_lifetime` and `renew_lifetime`.

##### Windows

Extending ticket lifetime can also be done within several clicks in Windows,
here is a step-by-step instruction:

  1. Open "Group Policy Management" (Start -> All Programs -> Administrative
  Tools -> Group Policy Management).  2. Select default domain (Domains
  -> default.domain -> Domain Controllers -> Default Domain Controllers;
  then on the right detail panel Settings -> Policies -> Windows Settings
  -> Security Settings -> right click "Local Policies/Security Options"
  -> Edit... to open Group Policy Management Editor).  3. Then in the GPM
  Editor Default Domain Controllers Policy -> Computer Configure -> Polices
  -> Windows Settings -> Security Settings -> Account Policies -> Kerberos
  Policies -> Maximum lifetime for service/user ticket.

Once the tgt ticket is expired, on Linux use command `kinit -R` to renew
the ticket, while on Windows, one should logout and logon again.

### Trouble Shoot Authentication Problems

  1. Check the Kerberos KDC log first, on Linux it is `/var/log/krb5kdc.log`
  by default or specified in /etc/krb5.conf.  On Windows, steps are: Start
  -> Administrative Tools -> Event Viewer, Windows Logs -> Security, to see
  whether the ticket to requested service has been issued. If not issued,
  verify whether both service principal name and user principal name are
  correct. In addition, corresponding principals have been created in the
  KDC server.  2. If tickets are issued, while authentication still fails
  and you're on *nix box, make sure the initial credential to the service
  principal's ticket is saved in the keytab. What's more, the keytab can be
  read by Kerberos KDC.

### References

* [MIT Kerberos Official Documents for Administrators][2]
* [A Step-by-step Guide for Windows Server 2008 Domain Controller and DNS Setup][3]
* [Add Windows Box to a *nix krb5kdc Domain][5]
* [Authenticate Linux Clients with Active Directory][6]
* [Install Plugin in MariaDB][7]
* [Kerberos Principal Name Specification][8]
* [Renew a ticket on Windows][9]
* [\*nix krenew command: Extend Ticket Lifetime on \*nix][10]

[1]: http://web.mit.edu/kerberos/
[2]: http://web.mit.edu/kerberos/krb5-latest/doc/admin/index.html
[3]: http://www.windowsreference.com/windows-server-2008/step-by-step-guide-for-windows-server-2008-domain-controller-and-dns-server-setup/
[5]: http://social.technet.microsoft.com/wiki/contents/articles/2751.kerberos-interoperability-step-by-step-guide-for-windows-server-2003.aspx#Using_an_MIT_KDC_with_a_Stand-alone_Windows_Server_TwentyOhThree_Client
[6]: http://technet.microsoft.com/en-us/magazine/2008.12.linux.aspx
[7]: https://kb.askmonty.org/en/plugin-overview/#installing-plugins
[8]: http://pic.dhe.ibm.com/infocenter/iseries/v6r1m0/index.jsp?topic=/cl/addkrbtkt.htm
[9]: http://technet.microsoft.com/en-us/library/cc738673(v=ws.10).aspx#w2k8tr_kerb_tools_iybi
[10]: http://stackoverflow.com/questions/14682153/lifetime-of-kerberos-tickets#15457265
