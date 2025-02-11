package app

import (
	"encoding/gob"
	"flag"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	uuid "github.com/nu7hatch/gouuid"
)

var LDAPSessions map[string]*LDAPClient
var APIVersion = "1.0.4"

func Run() {
	gob.Register(LDAPClient{})

	log.Printf("Starting ProxmoxAAS-LDAP version %s\n", APIVersion)

	configPath := flag.String("config", "config.json", "path to config.json file")
	flag.Parse()

	config, err := GetConfig(*configPath)
	if err != nil {
		log.Fatal("Error when reading config file: ", err)
	}
	log.Printf("Read in config from %s\n", *configPath)

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	store := cookie.NewStore([]byte(config.SessionSecretKey))
	store.Options(sessions.Options{
		Path:     config.SessionCookie.Path,
		HttpOnly: config.SessionCookie.HttpOnly,
		Secure:   config.SessionCookie.Secure,
		MaxAge:   config.SessionCookie.MaxAge,
	})
	router.Use(sessions.Sessions(config.SessionCookieName, store))

	log.Printf("Started API router and cookie store (Name: %s Params: %+v)\n", config.SessionCookieName, config.SessionCookie)

	LDAPSessions = make(map[string]*LDAPClient)

	router.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"version": APIVersion})
	})

	router.POST("/ticket", func(c *gin.Context) {
		var body Login
		if err := c.ShouldBind(&body); err != nil { // bad request from binding
			c.JSON(http.StatusBadRequest, gin.H{"auth": false, "error": err.Error()})
			return
		}

		newLDAPClient, err := NewLDAPClient(config)
		if err != nil { // failed to dial ldap server, considered a server error
			c.JSON(http.StatusInternalServerError, gin.H{"auth": false, "error": err.Error()})
			return
		}
		err = newLDAPClient.BindUser(body.Username, body.Password)
		if err != nil { // failed to authenticate, return error
			c.JSON(http.StatusBadRequest, gin.H{"auth": false, "error": err.Error()})
			return
		}

		// successful binding at this point
		// create new session
		session := sessions.Default(c)
		// create (hopefully) safe uuid to map to ldap session
		uuid, _ := uuid.NewV4()
		// set uuid mapping in session
		session.Set("SessionUUID", uuid.String())
		// set uuid mapping in LDAPSessions
		LDAPSessions[uuid.String()] = newLDAPClient
		// save the session
		session.Save()
		// return successful auth
		c.JSON(http.StatusOK, gin.H{"auth": true})
	})

	router.DELETE("/ticket", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		delete(LDAPSessions, uuid)
		session.Options(sessions.Options{MaxAge: -1}) // set max age to -1 so it is deleted
		_ = session.Save()
		c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
	})

	router.GET("/users", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		status, res := LDAPSession.GetAllUsers()
		c.JSON(status, HandleResponse(res))
	})

	router.POST("/users/:userid", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		// check if user already exists
		status, res := LDAPSession.GetUser(c.Param("userid"))
		if status != 200 && ldap.IsErrorWithCode(res["error"].(error), ldap.LDAPResultNoSuchObject) { // user does not already exist, create new user
			var body UserRequired                       // all user attributes required for new users
			if err := c.ShouldBind(&body); err != nil { // attempt to bind user data
				c.JSON(http.StatusBadRequest, gin.H{"auth": false, "error": err.Error()})
				return
			}
			status, res = LDAPSession.AddUser(c.Param("userid"), body)
			c.JSON(status, HandleResponse(res))
		} else { // user already exists, attempt to modify user
			var body UserOptional                       // all user attributes optional for new users
			if err := c.ShouldBind(&body); err != nil { // attempt to bind user data
				c.JSON(http.StatusBadRequest, gin.H{"auth": false, "error": err.Error()})
				return
			}
			status, res = LDAPSession.ModUser(c.Param("userid"), body)
			c.JSON(status, HandleResponse(res))
		}
	})

	router.GET("/users/:userid", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		status, res := LDAPSession.GetUser(c.Param("userid"))
		c.JSON(status, HandleResponse(res))
	})

	router.DELETE("/users/:userid", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		status, res := LDAPSession.DelUser(c.Param("userid"))
		c.JSON(status, HandleResponse(res))
	})

	router.GET("/groups", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		status, res := LDAPSession.GetAllGroups()
		c.JSON(status, HandleResponse(res))
	})

	router.GET("/groups/:groupid", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		status, res := LDAPSession.GetGroup(c.Param("groupid"))
		c.JSON(status, HandleResponse(res))
	})

	router.POST("/groups/:groupid", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		var body Group
		if err := c.ShouldBind(&body); err != nil { // bad request from binding
			c.JSON(http.StatusBadRequest, gin.H{"auth": false, "error": err.Error()})
			return
		}

		// check if group already exists
		status, res := LDAPSession.GetGroup(c.Param("groupid"))
		if status != 200 && ldap.IsErrorWithCode(res["error"].(error), ldap.LDAPResultNoSuchObject) { // group does not already exist, create new group
			status, res = LDAPSession.AddGroup(c.Param("groupid"), body)
			c.JSON(status, HandleResponse(res))
		} else { // group already exists, attempt to modify group
			status, res = LDAPSession.ModGroup(c.Param("groupid"), body)
			c.JSON(status, HandleResponse(res))
		}
	})

	router.DELETE("/groups/:groupid", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		status, res := LDAPSession.DelGroup(c.Param("groupid"))
		c.JSON(status, HandleResponse(res))
	})

	router.POST("/groups/:groupid/members/:userid", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		status, res := LDAPSession.AddUserToGroup(c.Param("userid"), c.Param("groupid"))
		c.JSON(status, HandleResponse(res))
	})

	router.DELETE("/groups/:groupid/members/:userid", func(c *gin.Context) {
		session := sessions.Default(c)
		SessionUUID := session.Get("SessionUUID")
		if SessionUUID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}
		uuid := SessionUUID.(string)
		LDAPSession := LDAPSessions[uuid]
		if LDAPSession == nil { // does not have registered ldap session associated with cookie session
			c.JSON(http.StatusUnauthorized, gin.H{"auth": false})
			return
		}

		status, res := LDAPSession.DelUserFromGroup(c.Param("userid"), c.Param("groupid"))
		c.JSON(status, HandleResponse(res))
	})

	log.Printf("Starting LDAP API on port %s\n", strconv.Itoa(config.ListenPort))

	router.Run("0.0.0.0:" + strconv.Itoa(config.ListenPort))
}
