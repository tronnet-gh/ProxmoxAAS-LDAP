package tests

import (
	"fmt"
	"math/rand"
	"net/http"
	"proxmoxaas-ldap/app"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

func RandInt(min int, max int) int {
	return rand.Intn(max+1-min) + min
}

func RandString(n int) string {
	var letters = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// random ldap style DN
func RandDN(n int) string {
	return fmt.Sprintf("cn=%s,ou=%s,dc=%s,dc=%s", RandString(n), RandString(n), RandString(n), RandString(n))
}

// typically for testing values of a variable
func AssertEquals[T comparable](t *testing.T, label string, a T, b T) {
	t.Helper()
	if a != b {
		t.Errorf(`%s = %#v; expected %#v.`, label, a, b)
	}
}

// asserting the success or failure of a generic error
func AssertError(t *testing.T, label string, gotErr error, expectErr error) {
	t.Helper()
	if gotErr != nil && expectErr != nil {
		if gotErr.Error() != expectErr.Error() {
			t.Errorf(`%s returned %s; expected %s`, label, gotErr.Error(), expectErr.Error())
		}
	} else {
		if gotErr != expectErr {
			t.Errorf(`%s returned %s; expected %s`, label, gotErr.Error(), expectErr.Error())
		}
	}
}

// typically for asserting the success or failure of an ldap result
func AssertLDAPError(t *testing.T, label string, gotErr any, expectErrCode uint16) {
	t.Helper()
	expectError := ldap.LDAPResultCodeMap[expectErrCode]
	if expectErrCode == ldap.LDAPResultSuccess { // expect success
		if gotErr != nil { // got an error
			gotErr := gotErr.(error)
			t.Errorf(`%s returned %s; expected %s.`, label, gotErr.Error(), "success")
		} // did not get an error
	} else { // expect error
		if gotErr == nil { // did not get an error
			t.Errorf(`%s returned %s; expected %s.`, label, "success", expectError)
			return
		}
		gotErr := gotErr.(error)
		if !ldap.IsErrorWithCode(gotErr, expectErrCode) { // got an error that does not match the expected error
			t.Errorf(`%s returned %s; expected %s.`, label, gotErr.Error(), expectError)
		} // got the expected error
	}
}

// typically for asserting the success or failure of an http result
func AssertStatus(t *testing.T, label string, gotCode int, expectCode int) {
	t.Helper()
	if expectCode == http.StatusOK {
		if gotCode != http.StatusOK { // got an error
			t.Errorf(`%s returned %d; expected %d.`, label, gotCode, expectCode)
		}
	} else { // expect error
		if gotCode == http.StatusOK { // did not get an error
			t.Errorf(`%s returned %d; expected %d.`, label, gotCode, expectCode)
		} else if gotCode != expectCode { // got an error that does not match the expected error
			t.Errorf(`%s returned %d; expected %d.`, label, gotCode, expectCode)
		}
	}
}

// compare if two users are equal, accepts LDAPUser or gin.H
func AssertLDAPUserEquals(t *testing.T, label string, a any, b app.LDAPUser) {
	t.Helper()

	aObj, ok := a.(app.LDAPUser)
	if ok {
		if !reflect.DeepEqual(aObj, b) {
			t.Errorf(`%s = %#v; expected %#v.`, label, aObj, b)
		}
		return
	}

	aGin, ok := a.(gin.H)
	if ok {
		bGin := app.LDAPUserToGin(b)
		if !reflect.DeepEqual(aGin, bGin) {
			t.Errorf(`%s = %#v; expected %#v.`, label, aGin, bGin)
		}
		return
	}

	// not a supported type
	t.Errorf(`%s = %#v; expected %#v.`, label, a, b)
}

// compare if two users are equal, accepts LDAPUser or gin.H
func AssertLDAPGroupEquals(t *testing.T, label string, a any, b app.LDAPGroup) {
	t.Helper()

	aObj, ok := a.(app.LDAPGroup)
	if ok {
		if !reflect.DeepEqual(aObj, b) {
			t.Errorf(`%s = %#v; expected %#v.`, label, aObj, b)
		}
		return
	}

	aGin, ok := a.(gin.H)
	if ok {
		bGin := app.LDAPGroupToGin(b)
		if !reflect.DeepEqual(aGin, bGin) {
			t.Errorf(`%s = %#v; expected %#v.`, label, aGin, bGin)
		}
		return
	}

	// not a supported type
	t.Errorf(`%s = %#v; expected %#v.`, label, a, b)
}

var _config, _ = app.GetConfig("test_config.json")
var BaseDN = _config.BaseDN
var PeopleDN = fmt.Sprintf("ou=people,%s", BaseDN)
var GroupDN = fmt.Sprintf("ou=groups,%s", BaseDN)

type User struct {
	username string
	password string
	userObj  app.LDAPUser
}

type Group struct {
	groupname string
	groupObj  app.LDAPGroup
}
