package tests

import (
	"errors"
	"fmt"
	app "proxmoxaas-ldap/app"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

// test the GetConfig utility function because it used in other tests
func TestConfig_ValidPath(t *testing.T) {
	config, err := app.GetConfig("test_config.json")

	AssertError(t, "GetConfig()", err, nil)
	AssertEquals(t, "config.ListenPort", config.ListenPort, 80)
	AssertEquals(t, "config.LdapURL", config.LdapURL, "ldap://localhost")
	AssertEquals(t, "config.BaseDN", config.BaseDN, "dc=test,dc=paasldap")
	AssertEquals(t, "config.SessionCookieName", config.SessionCookieName, "PAASLDAPAuthTicket")
	AssertEquals(t, "config.SessionCookie.Path", config.SessionCookie.Path, "/")
	AssertEquals(t, "config.SessionCookie.HttpOnly", config.SessionCookie.HttpOnly, true)
	AssertEquals(t, "config.SessionCookie.Secure", config.SessionCookie.Secure, false)
	AssertEquals(t, "config.SessionCookie.MaxAge", config.SessionCookie.MaxAge, 7200)
}

func TestConfig_InvalidPath(t *testing.T) {
	badFileName := RandString(16)
	_, err := app.GetConfig(badFileName)
	expectedErr := fmt.Errorf("open %s: no such file or directory", badFileName)
	AssertError(t, "GetConfig()", err, expectedErr)

	_, err = app.GetConfig("bad_config.json")
	expectedErr = fmt.Errorf("invalid character ',' looking for beginning of object key string")
	AssertError(t, "GetConfig()", err, expectedErr)
}

// test the LDAPEntryToUser and LDAPUserToGin utility functions
func TestLDAPUserDataPipeline(t *testing.T) {
	var memberOf []string
	for i := 0; i < RandInt(5, 20); i++ {
		memberOf = append(memberOf, RandDN(16))
	}

	expectedUser := app.LDAPUser{
		DN: RandDN(16),
		Attributes: app.LDAPUserAttributes{
			CN:       RandString(16),
			SN:       RandString(16),
			Mail:     RandString(16),
			UID:      RandString(16),
			MemberOf: memberOf,
		},
	}

	attributes := make(map[string][]string)
	attributes["cn"] = []string{expectedUser.Attributes.CN}
	attributes["sn"] = []string{expectedUser.Attributes.SN}
	attributes["mail"] = []string{expectedUser.Attributes.Mail}
	attributes["uid"] = []string{expectedUser.Attributes.UID}
	attributes["memberOf"] = expectedUser.Attributes.MemberOf

	entry := ldap.NewEntry(expectedUser.DN, attributes)

	user := app.LDAPEntryToLDAPUser(entry)
	AssertLDAPUserEquals(t, "LDAPEntryToLDAPUser(entry) -> user", user, expectedUser)

	json := app.LDAPUserToGin(user)
	AssertLDAPUserEquals(t, "LDAPUserToGin(user) -> json", json, expectedUser)
}

// test the LDAPEntryToGroup and LDAPGroupToGin utility functions
func TestLDAPGroupDataPipeline(t *testing.T) {
	var member []string
	for i := 0; i < RandInt(5, 20); i++ {
		member = append(member, RandDN(16))
	}

	expectedGroup := app.LDAPGroup{
		DN: RandDN(16),
		Attributes: app.LDAPGroupAttributes{
			Member: member,
		},
	}

	attributes := make(map[string][]string)
	attributes["member"] = expectedGroup.Attributes.Member

	entry := ldap.NewEntry(expectedGroup.DN, attributes)

	group := app.LDAPEntryToLDAPGroup(entry)
	AssertLDAPGroupEquals(t, "LDAPEntryToLDAPGroup(entry) -> group", group, expectedGroup)

	json := app.LDAPGroupToGin(group)
	AssertLDAPGroupEquals(t, "LDAPGroupToGin(group) -> json", json, expectedGroup)
}

func TestHandleResponse(t *testing.T) {
	for errorCode := range ldap.LDAPResultCodeMap {
		expectedMessage := RandString(16)
		LDAPerr := ldap.NewError(errorCode, errors.New(expectedMessage))
		res := gin.H{
			"error": LDAPerr,
		}
		LDAPResult := ldap.LDAPResultCodeMap[errorCode]

		handledResponseError := (app.HandleResponse(res))["error"].(gin.H)

		AssertEquals(t, `HandleResponse(res)["error"]["code"]`, handledResponseError["code"].(uint16), errorCode)
		AssertEquals(t, `HandleResponse(res)["error"]["result"]`, handledResponseError["result"].(string), LDAPResult)
		AssertEquals(t, `HandleResponse(res)["error"]["message"]`, handledResponseError["message"].(string), expectedMessage)
	}

	res := gin.H{
		"ok":     true,
		"status": RandInt(0, 600),
	}

	handledResponse := app.HandleResponse(res)

	AssertEquals(t, `HandleResponse(res)["ok"]`, handledResponse["ok"].(bool), res["ok"].(bool))
	AssertEquals(t, `HandleResponse(res)["satus"]`, handledResponse["status"].(int), res["status"].(int))
	AssertEquals(t, `HandleResponse(res)["error"]`, handledResponse["error"], nil)
}
