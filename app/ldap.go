package app

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

// LDAPClient wrapper struct containing the connection, baseDN, peopleDN, and groupsDN
type LDAPClient struct {
	client   *ldap.Conn
	basedn   string
	peopledn string
	groupsdn string
}

// returns a new LDAPClient from the config
func NewLDAPClient(config Config) (*LDAPClient, error) {
	LDAPConn, err := ldap.DialURL(config.LdapURL)
	return &LDAPClient{
		client:   LDAPConn,
		basedn:   config.BaseDN,
		peopledn: "ou=people," + config.BaseDN,
		groupsdn: "ou=groups," + config.BaseDN,
	}, err
}

// bind a user using username and password to the LDAPClient
func (l LDAPClient) BindUser(username string, password string) error {
	userdn := fmt.Sprintf("uid=%s,%s", username, l.peopledn)
	return l.client.Bind(userdn, password)
}

func (l LDAPClient) GetAllUsers() (int, gin.H) {
	searchRequest := ldap.NewSearchRequest(
		l.peopledn, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=inetOrgPerson))",                      // The filter to apply
		[]string{"dn", "cn", "sn", "mail", "uid", "memberOf"}, // A list attributes to retrieve
		nil,
	)

	searchResponse, err := l.client.Search(searchRequest) // perform search
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	var results = []gin.H{} // create list of results

	for _, entry := range searchResponse.Entries { // for each result,
		user := LDAPEntryToLDAPUser(entry)
		results = append(results, LDAPUserToGin(user))
	}

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
		"users": results,
	}
}

func (l LDAPClient) GetUser(uid string) (int, gin.H) {
	searchRequest := ldap.NewSearchRequest( //  setup search for user by uid
		fmt.Sprintf("uid=%s,%s", uid, l.peopledn), // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=inetOrgPerson))",                      // The filter to apply
		[]string{"dn", "cn", "sn", "mail", "uid", "memberOf"}, // A list attributes to retrieve
		nil,
	)

	searchResponse, err := l.client.Search(searchRequest) // perform search
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	entry := searchResponse.Entries[0]

	user := LDAPEntryToLDAPUser(entry)
	result := LDAPUserToGin(user)

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
		"user":  result,
	}
}

func (l LDAPClient) AddUser(uid string, user UserRequired) (int, gin.H) {
	if user.CN == "" || user.SN == "" || user.UserPassword == "" || user.Mail == "" {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": "Missing one of required fields: cn, sn, mail, userpassword",
		}
	}

	addRequest := ldap.NewAddRequest(
		fmt.Sprintf("uid=%s,%s", uid, l.peopledn), // DN
		nil, // controls
	)
	addRequest.Attribute("sn", []string{user.SN})
	addRequest.Attribute("cn", []string{user.CN})
	addRequest.Attribute("mail", []string{user.Mail})
	addRequest.Attribute("userPassword", []string{user.UserPassword})
	addRequest.Attribute("objectClass", []string{"inetOrgPerson"})

	err := l.client.Add(addRequest)
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
	}
}

func (l LDAPClient) ModUser(uid string, user UserOptional) (int, gin.H) {
	if user.CN == "" && user.SN == "" && user.UserPassword == "" && user.Mail == "" {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": "Requires one of fields: cn, sn, mail, userpassword",
		}
	}

	modifyRequest := ldap.NewModifyRequest(
		fmt.Sprintf("uid=%s,%s", uid, l.peopledn),
		nil,
	)
	if user.CN != "" {
		modifyRequest.Replace("cn", []string{user.CN})
	}
	if user.SN != "" {
		modifyRequest.Replace("sn", []string{user.SN})
	}
	if user.Mail != "" {
		modifyRequest.Replace("mail", []string{user.Mail})
	}
	if user.UserPassword != "" {
		modifyRequest.Replace("userPassword", []string{user.UserPassword})
	}

	err := l.client.Modify(modifyRequest)
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
	}
}

func (l LDAPClient) DelUser(uid string) (int, gin.H) {
	userDN := fmt.Sprintf("uid=%s,%s", uid, l.peopledn)

	// assumes that olcMemberOfRefint=true updates member attributes of referenced groups

	deleteUserRequest := ldap.NewDelRequest( // setup delete request
		userDN,
		nil,
	)

	err := l.client.Del(deleteUserRequest) // delete user
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
	}
}

func (l LDAPClient) GetAllGroups() (int, gin.H) {
	searchRequest := ldap.NewSearchRequest(
		l.groupsdn, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=groupOfNames))", // The filter to apply
		[]string{"cn", "member"},        // A list attributes to retrieve
		nil,
	)

	searchResponse, err := l.client.Search(searchRequest) // perform search
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	var results = []gin.H{} // create list of results

	for _, entry := range searchResponse.Entries { // for each result,
		group := LDAPEntryToLDAPGroup(entry)
		results = append(results, LDAPGroupToGin(group))
	}

	return http.StatusOK, gin.H{
		"ok":     true,
		"error":  nil,
		"groups": results,
	}
}

func (l LDAPClient) GetGroup(gid string) (int, gin.H) {
	searchRequest := ldap.NewSearchRequest( //  setup search for user by uid
		fmt.Sprintf("cn=%s,%s", gid, l.groupsdn), // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=groupOfNames))", // The filter to apply
		[]string{"cn", "member"},        // A list attributes to retrieve
		nil,
	)

	searchResponse, err := l.client.Search(searchRequest) // perform search
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	entry := searchResponse.Entries[0]
	group := LDAPEntryToLDAPGroup(entry)
	result := LDAPGroupToGin(group)

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
		"group": result,
	}
}

func (l LDAPClient) AddGroup(gid string, group Group) (int, gin.H) {
	addRequest := ldap.NewAddRequest(
		fmt.Sprintf("cn=%s,%s", gid, l.groupsdn), // DN
		nil,                                      // controls
	)
	addRequest.Attribute("cn", []string{gid})
	addRequest.Attribute("member", []string{""})
	addRequest.Attribute("objectClass", []string{"groupOfNames"})

	err := l.client.Add(addRequest)
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
	}
}

func (l LDAPClient) ModGroup(gid string, group Group) (int, gin.H) {
	return 200, gin.H{
		"ok":    true,
		"error": nil,
	}
}

func (l LDAPClient) DelGroup(gid string) (int, gin.H) {
	groupDN := fmt.Sprintf("cn=%s,%s", gid, l.groupsdn)

	// assumes that memberOf overlay will automatically update referenced memberOf attributes

	deleteGroupRequest := ldap.NewDelRequest( // setup delete request
		groupDN,
		nil,
	)

	err := l.client.Del(deleteGroupRequest) // delete group
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
	}
}

func (l LDAPClient) AddUserToGroup(uid string, gid string) (int, gin.H) {
	userDN := fmt.Sprintf("uid=%s,%s", uid, l.peopledn)
	groupDN := fmt.Sprintf("cn=%s,%s", gid, l.groupsdn)

	modifyRequest := ldap.NewModifyRequest( // modify group member value
		groupDN,
		nil,
	)

	modifyRequest.Add("member", []string{userDN}) // add user to group member attribute

	err := l.client.Modify(modifyRequest) // modify group
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
	}
}

func (l LDAPClient) DelUserFromGroup(uid string, gid string) (int, gin.H) {
	userDN := fmt.Sprintf("uid=%s,%s", uid, l.peopledn)
	groupDN := fmt.Sprintf("cn=%s,%s", gid, l.groupsdn)

	modifyRequest := ldap.NewModifyRequest( // modify group member value
		groupDN,
		nil,
	)

	modifyRequest.Delete("member", []string{userDN}) // remove user from group member attribute

	err := l.client.Modify(modifyRequest) // modify group
	if err != nil {
		return http.StatusBadRequest, gin.H{
			"ok":    false,
			"error": err,
		}
	}

	return http.StatusOK, gin.H{
		"ok":    true,
		"error": nil,
	}
}
