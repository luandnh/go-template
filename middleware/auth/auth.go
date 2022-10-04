package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/shaj13/go-guardian/v2/auth"
)

const (
	SECRET_TOKEN = "abc!@#abc123"
	SUPERADMIN   = "superadmin"
	ADMIN        = "admin"
	USER         = "user"
	LEADER       = "leader"
	MANAGER      = "manager"
	AGENT        = "agent"
)

type IAuthMiddleware interface {
	AuthMiddleware() gin.HandlerFunc
}

var AuthMdw IAuthMiddleware

func AuthMiddleware() gin.HandlerFunc {
	return AuthMdw.AuthMiddleware()
}

func GetUser(c *gin.Context) (*GoAuthUser, bool) {
	tmp, isExist := c.Get("user")
	if isExist {
		user, ok := tmp.(*GoAuthUser)
		return user, ok
	} else {
		return nil, false
	}
}

func GetUserId(c *gin.Context) (string, bool) {
	user, ok := GetUser(c)
	if !ok {
		return "", false
	} else {
		return user.Id, true
	}
}

func GetUserLevel(c *gin.Context) (string, bool) {
	user, ok := GetUser(c)
	if !ok {
		return "", false
	} else {
		return user.Level, true
	}
}

func GetUserDomainId(c *gin.Context) (string, bool) {
	user, ok := GetUser(c)
	if !ok {
		return "", false
	}
	domainUuid := user.DomainId
	if user.Level == SUPERADMIN {
		if tenantUuid := c.GetHeader("x-tenant-uuid"); len(tenantUuid) > 0 {
			domainUuid = tenantUuid
		}
	}
	return domainUuid, true
}

func GetUserName(c *gin.Context) (string, bool) {
	user, ok := GetUser(c)
	if !ok {
		return "", false
	} else {
		return user.Name, true
	}
}

type GoAuthUser struct {
	DomainId   string          `json:"domain_id"`
	DomainName string          `json:"domain_name"`
	Id         string          `json:"id"`
	Name       string          `json:"name"`
	Level      string          `json:"level"`
	Scopes     []string        `json:"scopes"`
	Extensions auth.Extensions `json:"extensions"`
	Groups     []string        `json:"groups"`
}

func NewGoAuthUser(name, id string, groups []string, extensions auth.Extensions, domainId, domainName, level string, scopes []string) GoAuthInfo {
	user := &GoAuthUser{
		DomainId:   domainId,
		DomainName: domainName,
		Level:      level,
		Scopes:     scopes,
	}
	user.Name = name
	user.Id = id
	user.Groups = groups
	user.Extensions = extensions
	return user
}

func (d *GoAuthUser) GetUserName() string {
	return d.Name
}
func (d *GoAuthUser) SetUserName(name string) {
	d.Name = name
}

func (d *GoAuthUser) GetID() string {
	return d.Id
}

func (d *GoAuthUser) SetID(id string) {
	d.Id = id
}

func (d *GoAuthUser) GetGroups() []string {
	return d.Groups
}

func (d *GoAuthUser) SetGroups(groups []string) {
	d.Groups = groups
}

func (d *GoAuthUser) GetExtensions() auth.Extensions {
	if d.Extensions == nil {
		d.Extensions = auth.Extensions{}
	}
	return d.Extensions
}

func (d *GoAuthUser) SetExtensions(exts auth.Extensions) {
	d.Extensions = exts
}

func (a *GoAuthUser) SetDomainId(domainId string) {
	a.DomainId = domainId
}

func (a *GoAuthUser) GetDomainId() string {
	return a.DomainId
}

func (a *GoAuthUser) SetDomainName(domainName string) {
	a.DomainName = domainName
}

func (a *GoAuthUser) GetDomainName() string {
	return a.DomainName
}

func (a *GoAuthUser) SetLevel(level string) {
	a.Level = level
}

func (a *GoAuthUser) GetLevel() string {
	return a.Level
}

func (a *GoAuthUser) SetScopes(scopes []string) {
	a.Scopes = scopes
}

func (a *GoAuthUser) GetScopes() []string {
	return a.Scopes
}

func CheckLevelManage() gin.HandlerFunc {
	return func(c *gin.Context) {
		level, ok := GetUserLevel(c)
		if !ok {
			c.JSON(http.StatusForbidden, map[string]interface{}{
				"error": http.StatusText(http.StatusUnauthorized),
			})
			return
		}
		if level != SUPERADMIN && level != ADMIN && level != MANAGER && level != LEADER {
			c.JSON(http.StatusForbidden, map[string]interface{}{
				"error": http.StatusText(http.StatusUnauthorized),
			})
			return
		}
	}
}
