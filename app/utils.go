package app

import (
	"encoding/json"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

type Config struct {
	ListenPort        int    `json:"listenPort"`
	LdapURL           string `json:"ldapURL"`
	BaseDN            string `json:"baseDN"`
	SessionSecretKey  string `json:"sessionSecretKey"`
	SessionCookieName string `json:"sessionCookieName"`
	SessionCookie     struct {
		Path     string `json:"path"`
		HttpOnly bool   `json:"httpOnly"`
		Secure   bool   `json:"secure"`
		MaxAge   int    `json:"maxAge"`
	}
}

func GetConfig(configPath string) (Config, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, err
	}
	var config Config
	err = json.Unmarshal(content, &config)
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

type Login struct { // login body struct
	Username string `form:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

type LDAPUserAttributes struct {
	CN       string
	SN       string
	Mail     string
	UID      string
	MemberOf []string
}

type LDAPUser struct {
	DN         string
	Attributes LDAPUserAttributes
}

func LDAPEntryToLDAPUser(entry *ldap.Entry) LDAPUser {
	return LDAPUser{
		DN: entry.DN,
		Attributes: LDAPUserAttributes{
			CN:       entry.GetAttributeValue("cn"),
			SN:       entry.GetAttributeValue("sn"),
			Mail:     entry.GetAttributeValue("mail"),
			UID:      entry.GetAttributeValue("uid"),
			MemberOf: entry.GetAttributeValues("memberOf"),
		},
	}
}

func LDAPUserToGin(user LDAPUser) gin.H {
	return gin.H{
		"dn": user.DN,
		"attributes": gin.H{
			"cn":       user.Attributes.CN,
			"sn":       user.Attributes.SN,
			"mail":     user.Attributes.Mail,
			"uid":      user.Attributes.UID,
			"memberOf": user.Attributes.MemberOf,
		},
	}
}

type LDAPGroupAttributes struct {
	CN     string
	Member []string
}

type LDAPGroup struct {
	DN         string
	Attributes LDAPGroupAttributes
}

func LDAPEntryToLDAPGroup(entry *ldap.Entry) LDAPGroup {
	return LDAPGroup{
		DN: entry.DN,
		Attributes: LDAPGroupAttributes{
			CN:     entry.GetAttributeValue("cn"),
			Member: entry.GetAttributeValues("member"),
		},
	}
}

func LDAPGroupToGin(group LDAPGroup) gin.H {
	return gin.H{
		"dn": group.DN,
		"attributes": gin.H{
			"cn":     group.Attributes.CN,
			"member": group.Attributes.Member,
		},
	}
}

type UserOptional struct { // add or modify user body struct
	CN           string `form:"cn"`
	SN           string `form:"sn"`
	Mail         string `form:"mail"`
	UserPassword string `form:"userpassword"`
}

type UserRequired struct { // add or modify user body struct
	CN           string `form:"cn" binding:"required"`
	SN           string `form:"sn" binding:"required"`
	Mail         string `form:"mail" binding:"required"`
	UserPassword string `form:"userpassword" binding:"required"`
}

type Group struct { // add or modify group body struct
}

func HandleResponse(response gin.H) gin.H {
	if response["error"] != nil {
		err := response["error"].(error)
		LDAPerr := err.(*ldap.Error)
		response["error"] = gin.H{
			"code":    LDAPerr.ResultCode,
			"result":  ldap.LDAPResultCodeMap[LDAPerr.ResultCode],
			"message": LDAPerr.Err.Error(),
		}
		return response
	} else {
		return response
	}
}
