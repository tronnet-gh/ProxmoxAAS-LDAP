package tests

// Assumes that the LDAP test server follows the PAAS-LDAP requirements which can be set using https://git.tronnet.net/tronnet/open-ldap-setup.
// Alternatively run `make dev-init` followed by `make test`.
// The integration tests ensures that the LDAP client maintains the security and access control of PAAS-LDAP but likely does not address integration with generic LDAP setups.

import (
	"fmt"
	"net/http"
	app "proxmoxaas-ldap/app"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

var AdminUser = User{
	username: "adminuser",
	password: "admin123",
	userObj: app.LDAPUser{
		DN: fmt.Sprintf("uid=adminuser,%s", PeopleDN),
		Attributes: app.LDAPUserAttributes{
			CN:   "admin",
			SN:   "user",
			UID:  "adminuser",
			Mail: "adminuser@test.paasldap",
			MemberOf: []string{
				fmt.Sprintf("cn=adminuser,%s", GroupDN),
				fmt.Sprintf("cn=admins,%s", GroupDN),
			},
		},
	},
}

var InvalidUser = User{
	username: RandString(16),
	password: RandString(16),
	userObj:  app.LDAPUser{},
}

var SampleUser = User{
	username: "sampleuser",
	password: "sample123",
	userObj: app.LDAPUser{
		DN: "uid=sampleuser,ou=people,dc=test,dc=paasldap",
		Attributes: app.LDAPUserAttributes{
			CN:       "sample",
			SN:       "user",
			UID:      "sampleuser",
			Mail:     "sampleuser@test.paasldap",
			MemberOf: []string{},
		},
	},
}

var UserDNMap = map[string]User{
	AdminUser.userObj.DN:  AdminUser,
	SampleUser.userObj.DN: SampleUser,
	// invalid user not included because it should not be added as a valid user
}

var AdminGroup = Group{
	groupname: "admins",
	groupObj: app.LDAPGroup{
		DN: fmt.Sprintf("cn=admins,%s", GroupDN),
		Attributes: app.LDAPGroupAttributes{
			CN: "admins",
			Member: []string{
				fmt.Sprintf("uid=adminuser,%s", PeopleDN),
			},
		},
	},
}

var AdminUserGroup = Group{
	groupname: "adminuser",
	groupObj: app.LDAPGroup{
		DN: fmt.Sprintf("cn=adminuser,%s", GroupDN),
		Attributes: app.LDAPGroupAttributes{
			CN: "adminuser",
			Member: []string{
				fmt.Sprintf("uid=adminuser,%s", PeopleDN),
			},
		},
	},
}

var SampleUserGroup = Group{
	groupname: "sampleuser",
	groupObj: app.LDAPGroup{
		DN: fmt.Sprintf("cn=sampleuser,%s", GroupDN),
		Attributes: app.LDAPGroupAttributes{
			CN: "sampleuser",
			Member: []string{
				"",
				fmt.Sprintf("uid=sampleuser,%s", PeopleDN),
			},
		},
	},
}

var InvalidGroup = Group{
	groupname: "invalid",
	groupObj: app.LDAPGroup{
		DN: fmt.Sprintf("cn=invalid,%s", GroupDN),
		Attributes: app.LDAPGroupAttributes{
			CN:     "invalid",
			Member: []string{},
		},
	},
}

var GroupDNMap = map[string]Group{
	AdminGroup.groupObj.DN:      AdminGroup,
	AdminUserGroup.groupObj.DN:  AdminUserGroup,
	SampleUserGroup.groupObj.DN: SampleUserGroup,
}

func TestClientBind(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertEquals(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// test a valid user bind which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// test an invalid user bind which should return invalid credentials
	err = client.BindUser(InvalidUser.username, InvalidUser.password)
	AssertLDAPError(t, "BindUser(InvalidUser)", err, ldap.LDAPResultInvalidCredentials)
}

func TestGetAllUsers(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// get all users anonymously which should succeed
	status, res := client.GetAllUsers()
	AssertStatus(t, "GetAllUsers() -> status", status, http.StatusOK)
	users := res["users"].([]gin.H)
	AssertEquals(t, "GetAllUsers() -> len(res)", len(users), 1)
	for i := 0; i < len(users); i++ {
		user := users[i]
		userDN := user["dn"].(string)
		expectedUserObj := UserDNMap[userDN].userObj
		AssertLDAPUserEquals(t, fmt.Sprintf("GetAllUsers() -> res[%d]", i), user, expectedUserObj)
	}

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ = client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// get all users with admin bind which should succeed
	status, res = client.GetAllUsers()
	AssertStatus(t, "GetAllUsers() -> status", status, http.StatusOK)
	users = res["users"].([]gin.H)
	AssertEquals(t, "GetAllUsers() -> len(res)", len(users), 2)
	for i := 0; i < len(users); i++ {
		user := users[i]
		userDN := user["dn"].(string)
		expectedUserObj := UserDNMap[userDN].userObj
		AssertLDAPUserEquals(t, fmt.Sprintf("GetAllUsers() -> res[%d]", i), user, expectedUserObj)
	}

	// bind using sample user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// get all users with sample user bind which should succeed
	status, res = client.GetAllUsers()
	AssertStatus(t, "GetAllUsers() -> status", status, http.StatusOK)
	users = res["users"].([]gin.H)
	AssertEquals(t, "GetAllUsers() -> len(res)", len(users), 2)
	for i := 0; i < len(users); i++ {
		user := users[i]
		userDN := user["dn"].(string)
		expectedUserObj := UserDNMap[userDN].userObj
		AssertLDAPUserEquals(t, fmt.Sprintf("GetAllUsers() -> res[%d]", i), user, expectedUserObj)
	}

	// rebind as admin user
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

// This contrived test shows how difficult it should be for GetAllUsers to return an error
func TestGetAllUsers_InvalidBaseDN(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	config.BaseDN = RandDN(16)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// get all users anonymously which should fail because of the incorrect DN
	status, res := client.GetAllUsers()
	AssertStatus(t, "GetAllUsers() -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "GetAllUsers() -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestGetUser_SelfUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// get the admin user which should return the expected user
	status, res := client.GetUser(AdminUser.username)
	AssertStatus(t, "GetUser(AdminUser) -> status", status, http.StatusOK)
	AssertLDAPUserEquals(t, "GetUser(AdminUser) -> result", res["user"], AdminUser.userObj)
}

func TestGetUser_OtherUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// bind using sample user credentials which should succeed
	err = client.BindUser(SampleUser.username, SampleUser.password)
	AssertLDAPError(t, "BindUser(SampleUser)", err, ldap.LDAPResultSuccess)

	// try reading the admin user, which should return the expected admin user
	status, res := client.GetUser(AdminUser.username)
	AssertStatus(t, "GetUser(AdminUser) -> status", status, http.StatusOK)
	AssertLDAPUserEquals(t, "GetUser(AdminUser) -> result", res["user"], AdminUser.userObj)

	// rebind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestGetUser_NoSuchUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// get the invalid user which should return NoSuchObject error
	status, res := client.GetUser(InvalidUser.username)
	AssertStatus(t, "GetUser(InvalidUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "GetUser(InvalidUser) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestModUser_SelfUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	modification := app.UserOptional{
		CN:           "testnewcn",
		SN:           "testnewsn",
		Mail:         "testnewmail@test.paasldap",
		UserPassword: "test345",
	}

	ModifiedUser := AdminUser
	ModifiedUser.userObj.Attributes.CN = modification.CN
	ModifiedUser.userObj.Attributes.SN = modification.SN
	ModifiedUser.userObj.Attributes.Mail = modification.Mail
	ModifiedUser.password = modification.UserPassword

	// try modification, which should succeed
	status, _ := client.ModUser(AdminUser.username, modification)
	AssertStatus(t, "ModUser(AdminUser -> ModifiedUser)", status, http.StatusOK)

	// try reading the update, which should return the expected updated user
	status, res := client.GetUser(ModifiedUser.username)
	AssertStatus(t, "GetUser(ModifiedUser) -> status", status, http.StatusOK)
	AssertLDAPUserEquals(t, "GetUser(ModifiedUser) -> result", res["user"], ModifiedUser.userObj)

	// try binding with the original password, which should fail with invalid credentials
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultInvalidCredentials)

	// try binding with the updated password, which should succeed
	err = client.BindUser(ModifiedUser.username, ModifiedUser.password)
	AssertLDAPError(t, "BindUser(ModifiedUser)", err, ldap.LDAPResultSuccess)

	modification = app.UserOptional{
		CN:           AdminUser.userObj.Attributes.CN,
		SN:           AdminUser.userObj.Attributes.SN,
		Mail:         AdminUser.userObj.Attributes.Mail,
		UserPassword: AdminUser.password,
	}

	// revert previous mod, which should not have errors
	status, _ = client.ModUser(ModifiedUser.username, modification)
	AssertStatus(t, "ModUser(ModifiedUser -> AdminUser)", status, http.StatusOK)

	// try reading the revert, which should return the expected original user
	status, res = client.GetUser(AdminUser.username)
	AssertStatus(t, "GetUser(AdminUser) -> status", status, http.StatusOK)
	AssertLDAPUserEquals(t, "GetUser(AdminUser) -> result", res["user"], AdminUser.userObj)

	// try binding with the original password, which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// try binding with the updated password, which should fail with invalid credentials
	err = client.BindUser(ModifiedUser.username, ModifiedUser.password)
	AssertLDAPError(t, "BindUser(ModifiedUser)", err, ldap.LDAPResultInvalidCredentials)
}

func TestModUser_OtherUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	newPassword := RandString(16)

	modification := app.UserOptional{
		UserPassword: newPassword,
	}

	// try password modification, which should succeed
	status, _ = client.ModUser(SampleUser.username, modification)
	AssertStatus(t, "ModUser(SampleUser -> ModifiedUser) -> status", status, http.StatusOK)

	// try binding with the original password, which should fail with invalid credentials
	err = client.BindUser(SampleUser.username, SampleUser.password)
	AssertLDAPError(t, "BindUser(SampleUser)", err, ldap.LDAPResultInvalidCredentials)

	// try binding with the updated password, which should succeed
	err = client.BindUser(SampleUser.username, newPassword)
	AssertLDAPError(t, "BindUser(ModifiedUser)", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	modification = app.UserOptional{
		CN: RandString(16),
	}

	// try cn modification, which should fail
	status, res := client.ModUser(SampleUser.username, modification)
	AssertStatus(t, "ModUser(SampleUser -> ModifiedUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "BindUser(ModifiedUser)", res["error"].(error), ldap.LDAPResultInsufficientAccessRights)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestModUser_NoSuchUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	modification := app.UserOptional{
		CN: "invalid",
	}

	// try modification, which should fail with NoSuchObject
	status, res := client.ModUser(InvalidUser.username, modification)
	AssertStatus(t, "ModUser(InvalidUser -> ModifiedUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "ModUser(InvalidUser -> ModifiedUser) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestModUser_InsufficientPermission(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// bind as the new sample user
	err = client.BindUser(SampleUser.username, SampleUser.password)
	AssertLDAPError(t, "BindUser(SampleUser)", err, ldap.LDAPResultSuccess)

	modification := app.UserOptional{
		CN: "invalid",
	}

	// try modification, which should fail with InsufficientAccessRights
	status, res := client.ModUser(AdminUser.username, modification)
	AssertStatus(t, "ModUser(AdminUser -> ModifiedUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "ModUser(AdminUser -> ModifiedUser) -> result", res["error"].(error), ldap.LDAPResultInsufficientAccessRights)

	// rebind as admin user
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestModUser_MissingRequiredField(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	modification := app.UserOptional{}

	// try modification, which should fail with mising one of cn, sn, mail, or userpassword
	status, res := client.ModUser(AdminUser.username, modification)
	AssertStatus(t, "ModUser(AdminUser -> ModifiedUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "ModUser(AdminUser -> ModifiedUser) -> result", res["error"].(error), ldap.LDAPResultUnwillingToPerform)
}

func TestModUser_NoAuth(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	newUser := app.UserOptional{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// test mod admin user as anonymous which should fail with AuthenticationRequired
	status, res := client.ModUser(AdminUser.username, newUser)
	AssertStatus(t, "ModUser(AdminUser -> SampleUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "ModUser(AdminUser -> SampleUser) -> result", res["error"].(error), ldap.LDAPResultStrongAuthRequired)
}

func TestAddGetDelUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// try reading the new user, which should return the expected sample user
	status, res := client.GetUser(SampleUser.username)
	AssertStatus(t, "GetUser(SampleUser) -> status", status, http.StatusOK)
	AssertLDAPUserEquals(t, "GetUser(SampleUser) -> result", res["user"], SampleUser.userObj)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)

	// try reading the new user, which should return a an error since it has been deleted
	status, res = client.GetUser(SampleUser.username)
	AssertStatus(t, "GetUser(SampleUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "GetUser(SampleUser) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestAddUser_DuplicateUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// try to create new sample user again, which should fail with object already exists
	status, res := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "AddUser(SampleUser) -> result", res["error"].(error), ldap.LDAPResultEntryAlreadyExists)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestAddUser_InsufficientPermission(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// bind as the sample user
	err = client.BindUser(SampleUser.username, SampleUser.password)
	AssertLDAPError(t, "BindUser(SampleUser)", err, ldap.LDAPResultSuccess)

	// try to create a new user, which should fail with insufficient permission
	status, res := client.AddUser(InvalidUser.username, newUser)
	AssertStatus(t, "AddUser(InvalidUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "AddUser(InvalidUser) -> result", res["error"].(error), ldap.LDAPResultInsufficientAccessRights)

	// rebind as admin user
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestAddUser_MissingRequiredField(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{}

	// try add invalid user, which should fail with mising all of cn, sn, mail, or userpassword
	status, res := client.AddUser(InvalidUser.username, newUser)
	AssertStatus(t, "AddUser(InvalidUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "AddUser(InvalidUser) -> result", res["error"].(error), ldap.LDAPResultUnwillingToPerform)
}

func TestAddUser_NoAuth(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// test add admin user as anonymous which should fail with AuthenticationRequired
	status, res := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "AddUser(SampleUser) -> result", res["error"].(error), ldap.LDAPResultStrongAuthRequired)
}

func TestDelUser_NoSuchUser(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// try delete invalid user, which should fail with NoSuchObject
	status, res := client.DelUser(InvalidUser.username)
	AssertStatus(t, "DelUser(InvalidUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "DelUser(InvalidUser) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestDelUser_InsufficientPermission(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// bind as the sample user
	err = client.BindUser(SampleUser.username, SampleUser.password)
	AssertLDAPError(t, "BindUser(SampleUser)", err, ldap.LDAPResultSuccess)

	// try delete admin user, which should fail with InsufficientAccessRights
	status, res := client.DelUser(AdminUser.username)
	AssertStatus(t, "DelUser(AdminUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "DelUser(AdminUser) -> result", res["error"].(error), ldap.LDAPResultInsufficientAccessRights)

	// rebind as admin user
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestDelUser_NoAuth(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// test delete admin user as anonymous which should fail with AuthenticationRequired
	status, res := client.DelUser(AdminUser.username)
	AssertStatus(t, "DelUser(AdminUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "DelUser(AdminUser) -> result", res["error"].(error), ldap.LDAPResultStrongAuthRequired)
}

func TestGetAllGroups(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// get all groups anonymously which should succeed
	status, res := client.GetAllGroups()
	AssertStatus(t, "GetAllGroups() -> status", status, http.StatusOK)
	groups := res["groups"].([]gin.H)
	AssertEquals(t, "GetAllGroups() -> len(res)", len(groups), 2)
	for i := 0; i < len(groups); i++ {
		group := groups[i]
		groupDN := group["dn"].(string)
		expectedGroupObj := GroupDNMap[groupDN].groupObj
		AssertLDAPGroupEquals(t, fmt.Sprintf("GetAllGroups() -> res[%d]", i), group, expectedGroupObj)
	}

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// get all groups as admin user which should succeed
	status, res = client.GetAllGroups()
	AssertStatus(t, "GetAllGroups() -> status", status, http.StatusOK)
	groups = res["groups"].([]gin.H)
	AssertEquals(t, "GetAllGroups() -> len(res)", len(groups), 2)
	for i := 0; i < len(groups); i++ {
		group := groups[i]
		groupDN := group["dn"].(string)
		expectedGroupObj := GroupDNMap[groupDN].groupObj
		AssertLDAPGroupEquals(t, fmt.Sprintf("GetAllGroups() -> res[%d]", i), group, expectedGroupObj)
	}
}

// This contrived test shows how difficult it should be for GetAllGroups to return an error
func TestGetAllGroups_InvalidBaseDN(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	config.BaseDN = RandDN(16)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// get all groups anonymously which should fail because of the incorrect DN
	status, res := client.GetAllGroups()
	AssertStatus(t, "GetAllGroups() -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "GetAllGroups() -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestGetGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// test get admin group anonymously which should succeed
	status, res := client.GetGroup(AdminGroup.groupname)
	AssertStatus(t, "GetGroup(AdminGroup) -> status", status, http.StatusOK)
	AssertLDAPGroupEquals(t, "GetAllGroups(AdminGroup) -> result", res["group"], AdminGroup.groupObj)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// test get admin group as admin user which should succeed
	status, res = client.GetGroup(AdminGroup.groupname)
	AssertStatus(t, "GetGroup(AdminGroup) -> status", status, http.StatusOK)
	AssertLDAPGroupEquals(t, "GetGroup(AdminGroup) -> result", res["group"], AdminGroup.groupObj)
}

func TestGetGroup_NoSuchGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// test get invalid group anonymously which should fail with NoSuchObject
	status, res := client.GetGroup(InvalidGroup.groupname)
	AssertStatus(t, "GetGroup(InvalidGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "GetGroup(InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// test get invalid group as admin user which should fail with NoSuchObject
	status, res = client.GetGroup(InvalidGroup.groupname)
	AssertStatus(t, "GetGroup(InvalidGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "GetGroup(InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

// ModGroup does nothing since LDAP GroupOfNames does not store any attributes except CN and Members.
// CN should not be changed and Members should be added or removed using the appropriate functions.
// TODO update this when the function actually produces proper results
func TestModGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// test mod admin group as admin which should succeed
	status, _ := client.ModGroup(AdminGroup.groupname, app.Group{})
	AssertStatus(t, "ModGroup(AdminGroup -> AdminGroup) -> status", status, http.StatusOK)

	// test get admin group as admin user which should return the same admin group since no operation has been done
	status, res := client.GetGroup(AdminGroup.groupname)
	AssertStatus(t, "GetGroup(AdminGroup) -> status", status, http.StatusOK)
	AssertLDAPGroupEquals(t, "GetGroup(AdminGroup) -> result", res["group"], AdminGroup.groupObj)
}

func TestModGroup_NoSuchGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// test mod invalid group as sample user which should fail with InsufficientPermission
	status, res := client.ModGroup(InvalidGroup.groupname, app.Group{})
	AssertStatus(t, "ModGroup(InvalidGroup -> InvalidGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "ModGroup(InvalidGroup -> InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestModGroup_InsufficientPermission(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// bind as the sample user
	err = client.BindUser(SampleUser.username, SampleUser.password)
	AssertLDAPError(t, "BindUser(SampleUser)", err, ldap.LDAPResultSuccess)

	// test mod admin group as sample user which should fail with InsufficientPermission
	status, res := client.ModGroup(AdminGroup.groupname, app.Group{})
	AssertStatus(t, "ModGroup(AdminGroup -> AdminGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "ModGroup(AdminGroup -> AdminGroup) -> result", res["error"].(error), ldap.LDAPResultInsufficientAccessRights)

	// rebind as admin user
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestModGroup_NoAuth(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// test mod admin group as anonymous which should fail with AuthenticationRequired
	status, res := client.ModGroup(AdminGroup.groupname, app.Group{})
	AssertStatus(t, "GetGroup(AdminGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "GetGroup(AdminGroup) -> result", res["error"].(error), ldap.LDAPResultStrongAuthRequired)
}

func TestAddGetDelGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newGroup := app.Group{}

	// create new sample user group
	status, _ := client.AddGroup(SampleUserGroup.groupname, newGroup)
	AssertStatus(t, "AddGroup(SampleUserGroup) -> status", status, http.StatusOK)

	// try reading the new group, which should return the expected sample group with no members
	status, res := client.GetGroup(SampleUserGroup.groupname)
	expectedGroup := SampleUserGroup.groupObj
	expectedGroup.Attributes.Member = []string{""} // override the expected members since we aren't testing that here
	AssertStatus(t, "GetGroup(SampleUserGroup) -> status", status, http.StatusOK)
	AssertLDAPGroupEquals(t, "GetGroup(SampleUserGroup) -> result", res["group"], expectedGroup)

	// delete the sample user group
	status, _ = client.DelGroup(SampleUserGroup.groupname)
	AssertStatus(t, "DelGroup(SampleUserGroup) -> status", status, http.StatusOK)

	// try reading the new group, which should return a an error since it has been deleted
	status, res = client.GetGroup(SampleUserGroup.groupname)
	AssertStatus(t, "GetUser(SampleUser) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "GetUser(SampleUser) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestAddGroup_DuplicateGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newGroup := app.Group{}

	// create new sample user group
	status, _ := client.AddGroup(SampleUserGroup.groupname, newGroup)
	AssertStatus(t, "AddGroup(SampleUserGroup) -> status", status, http.StatusOK)

	// try to create new sample user again, which should fail with object already exists
	status, res := client.AddGroup(SampleUserGroup.groupname, newGroup)
	AssertStatus(t, "AddGroup(SampleUserGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "AddGroup(SampleUserGroup) -> result", res["error"].(error), ldap.LDAPResultEntryAlreadyExists)

	// delete the sample group
	status, _ = client.DelGroup(SampleUserGroup.groupname)
	AssertStatus(t, "DelGroup(SampleUserGroup) -> status", status, http.StatusOK)
}

func TestAddGroup_InsufficientPermission(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// bind as the sample user
	err = client.BindUser(SampleUser.username, SampleUser.password)
	AssertLDAPError(t, "BindUser(SampleUser)", err, ldap.LDAPResultSuccess)

	newGroup := app.Group{}

	// try to create a new group, which should fail with insufficient permission
	status, res := client.AddGroup(InvalidGroup.groupname, newGroup)
	AssertStatus(t, "AddGroup(InvalidGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "AddGroup(InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultInsufficientAccessRights)

	// rebind as admin user
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestAddGroup_NoAuth(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	newGroup := app.Group{}

	// try to create a new group, which should fail with AuthenticationRequired
	status, res := client.AddGroup(InvalidGroup.groupname, newGroup)
	AssertStatus(t, "AddGroup(InvalidGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "AddGroup(InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultStrongAuthRequired)
}

func TestDelGroup_NoSuchGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// try delete invalid group, which should fail with NoSuchObject
	status, res := client.DelGroup(InvalidGroup.groupname)
	AssertStatus(t, "DelGroup(InvalidGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "DelGroup(InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)
}

func TestDelGroup_InsufficientPermission(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// bind as the sample user
	err = client.BindUser(SampleUser.username, SampleUser.password)
	AssertLDAPError(t, "BindUser(SampleUser)", err, ldap.LDAPResultSuccess)

	// try delete admin group, which should fail with InsufficientAccessRights
	status, res := client.DelGroup(AdminGroup.groupname)
	AssertStatus(t, "DelGroup(AdminGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "DelGroup(AdminGroup) -> result", res["error"].(error), ldap.LDAPResultInsufficientAccessRights)

	// rebind as admin user
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestDelGroup_NoAuth(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// test del admin group as anonymous which should fail with AuthenticationRequired
	status, res := client.DelGroup(InvalidGroup.groupname)
	AssertStatus(t, "DelGroup(InvalidGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "DelGroup(InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultStrongAuthRequired)
}

func TestAddDelUserToGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	newGroup := app.Group{}

	// try to create a new group, which should succeed
	status, _ = client.AddGroup(SampleUserGroup.groupname, newGroup)
	AssertStatus(t, "AddGroup(SampleUserGroup) -> status", status, http.StatusOK)

	// try adding sample user to the sample user group which should succeed
	status, _ = client.AddUserToGroup(SampleUser.username, SampleUserGroup.groupname)
	AssertStatus(t, "AddUserToGroup(SampleUser -> SampleUserGroup) -> status", status, http.StatusOK)

	// try reading the new group, which should return the expected sample group with member
	status, res := client.GetGroup(SampleUserGroup.groupname)
	AssertStatus(t, "GetGroup(SampleUserGroup) -> status", status, http.StatusOK)
	AssertLDAPGroupEquals(t, "GetGroup(SampleUserGroup) -> result", res["group"], SampleUserGroup.groupObj)

	// try removing sample user from the sample user group which should succeed
	status, _ = client.DelUserFromGroup(SampleUser.username, SampleUserGroup.groupname)
	AssertStatus(t, "DelUserFromGroup(SampleUser -> SampleUserGroup) -> status", status, http.StatusOK)

	// try reading the new group, which should return the expected sample group without any members
	status, res = client.GetGroup(SampleUserGroup.groupname)
	expectedGroup := SampleUserGroup.groupObj
	expectedGroup.Attributes.Member = []string{""} // override the expected members since we aren't testing that here
	AssertStatus(t, "GetGroup(SampleUserGroup) -> status", status, http.StatusOK)
	AssertLDAPGroupEquals(t, "GetGroup(SampleUserGroup) -> result", res["group"], expectedGroup)

	// delete the sample user group
	status, _ = client.DelGroup(SampleUserGroup.groupname)
	AssertStatus(t, "DelGroup(SampleUserGroup) -> status", status, http.StatusOK)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestAddUserToGroup_NoSuchGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// try adding sample user to the sample user group which should fail with NoSuchObject
	status, res := client.AddUserToGroup(SampleUser.username, SampleUserGroup.groupname)
	AssertStatus(t, "AddUserToGroup(SampleUser -> SampleUserGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "AddUserToGroup(InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}

func TestDelUserFromGroup_NoSuchGroup(t *testing.T) {
	// create client
	config, err := app.GetConfig("test_config.json")
	AssertError(t, "GetConfig()", err, nil)
	client, err := app.NewLDAPClient(config)
	AssertLDAPError(t, "NewLDAPClient()", err, ldap.LDAPResultSuccess)

	// bind using admin user credentials which should succeed
	err = client.BindUser(AdminUser.username, AdminUser.password)
	AssertLDAPError(t, "BindUser(AdminUser)", err, ldap.LDAPResultSuccess)

	newUser := app.UserRequired{
		CN:           SampleUser.userObj.Attributes.CN,
		SN:           SampleUser.userObj.Attributes.SN,
		Mail:         SampleUser.userObj.Attributes.Mail,
		UserPassword: SampleUser.password,
	}

	// create new sample user, which should succeed
	status, _ := client.AddUser(SampleUser.username, newUser)
	AssertStatus(t, "AddUser(SampleUser) -> status", status, http.StatusOK)

	// try adding sample user to the sample user group which should fail with NoSuchObject
	status, res := client.DelUserFromGroup(SampleUser.username, SampleUserGroup.groupname)
	AssertStatus(t, "DelUserFromGroup(SampleUser -> SampleUserGroup) -> status", status, http.StatusBadRequest)
	AssertLDAPError(t, "DelUserFromGroup(InvalidGroup) -> result", res["error"].(error), ldap.LDAPResultNoSuchObject)

	// delete the sample user
	status, _ = client.DelUser(SampleUser.username)
	AssertStatus(t, "DelUser(SampleUser) -> status", status, http.StatusOK)
}
