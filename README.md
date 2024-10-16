# ProxmoxAAS LDAP - Simple REST API for LDAP

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
    - ldapURL: url to the ldap server ie. `ldap://ldap.domain.net`
    - baseDN: base DN ie. `dc=domain,dc=net`
    - sessionSecretKey: random value used to randomize cookie values, replace with any sufficiently large random string
3. Run the binary