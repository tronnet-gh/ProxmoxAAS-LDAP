# ProxmoxAAS LDAP - Simple REST API for LDAP

PAAS-LDAP will be deprecated in the future. Future deployments will use [user-manager-api](https://git.tronnet.net/tronnet/user-manager-api) instead.

ProxmoxAAS LDAP provides a simple API for managing users and groups in a simplified LDAP server. Expected LDAP configuration can be initialized using [open-ldap-setup](https://git.tronnet.net/tronnet/open-ldap-setup). 

## Installation

### Prerequisites

- Initialized LDAP server with the following configuration
    - Structure
        - Users: ou=people,...
            - objectType: inetOrgPerson
            - At least 1 user which is a member of admin group
        - Groups: ou=groups,...
            - objectType: groupOfNames
            - At least 1 admin group
    - Permissions:
        - Admin group should have write access
        - Users should have write access to own attributes (cn, sn, userPassword)
        - Enable anonymous binding
    - Load MemberOf Policy:
        - olcMemberOfDangling: ignore
        - olcMemberOfRefInt: TRUE
        - olcMemberOfGroupOC: groupOfNames
        - olcMemberOfMemberAD: member
        - olcMemberOfMemberOfAD: memberOf
    - Password Policy and TLS are recommended but not required

### Installation

1. Download `proxmoxaas-ldap` binary and `template.config.json` file from [releases](https://git.tronnet.net/tronnet/ProxmoxAAS-LDAP/releases)
2. Rename `template.config.json` to `config.json` and modify:
    - listenPort: port for PAAS-LDAP to bind and listen on 
    - ldapURL: url to the ldap server ie. `ldap://ldap.local`
    - startTLS: true if backend LDAP supports StartTLS
    - basedn: base DN ie. `dc=domain,dc=net`
    - sessionCookieName: name of the session cookie
    - sessionCookie: specific cookie properties
        - path: cookie path
        - httpOnly: cookie http-only
        - secure: cookie secure
        - maxAge: cookie max-age
3. Run the binary

## Building and Testing from Source

Building requires the go toolchain. Testing requires the go toolchain, make, and apt. Currently only supports Debian.

### Building from Source

1. Clone the repository
2. Run `go get` to get requirements
3. Run `make` to build the binary

### Testing Source

1. Clone the repository
2. Run `go get` to get requirements
3. Run `make dev-init` to install test requirements including openldap (slapd), ldap-utils, debconf-utils
4. Run `make test` to run all tests