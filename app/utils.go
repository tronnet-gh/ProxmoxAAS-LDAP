package app

import (
	"encoding/json"
	"log"
	"os"
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

func GetConfig(configPath string) Config {
	content, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal("Error when opening config file: ", err)
	}
	var config Config
	err = json.Unmarshal(content, &config)
	if err != nil {
		log.Fatal("Error during parsing config file: ", err)
	}
	return config
}

type Login struct { // login body struct
	Username string `form:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

type User struct { // add or modify user body struct
	CN           string `form:"cn"`
	SN           string `form:"sn"`
	UserPassword string `form:"userpassword"`
}

type Group struct { // add or modify group body struct
}
