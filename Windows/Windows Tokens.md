Windows uses access tokens to assign the necessary privileges to accounts for performing specific actions. These tokens are created when users log in or are authenticated, typically by LSASS.exe (the authentication process).

An access token consists of:

- **User SIDs (Security Identifiers)**
- **Group SIDs**
- **Privileges**
- And other related information.

There are two types of access tokens:

1. **Primary Access Tokens**: Associated with a user account and generated at logon.
2. **Impersonation Tokens**: Allow a process (or thread) to access resources using the token of another process or client.

Impersonation tokens come in different levels:

- **SecurityAnonymous**: Cannot impersonate another user.
- **SecurityIdentification**: Can get the identity and privileges of a client but cannot fully impersonate.
- **SecurityImpersonation**: Can impersonate the client's security context on the local system.
- **SecurityDelegation**: Can impersonate the client's security context on a remote system.

An account’s privileges, either assigned at creation or inherited from groups, enable specific actions. Commonly abused privileges include:

- **SeImpersonatePrivilege**
- **SeAssignPrimaryPrivilege**
- **SeTcbPrivilege**
- **SeBackupPrivilege**
- **SeRestorePrivilege**
- **SeCreateTokenPrivilege**
- **SeLoadDriverPrivilege**
- **SeTakeOwnershipPrivilege**
- **SeDebugPrivilege**

4o mini