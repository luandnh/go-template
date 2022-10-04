package auth

import (
	"callcenter-api/common/log"
	goauth "callcenter-api/middleware/auth/goauth"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
	"github.com/shaj13/go-guardian/v2/auth/strategies/union"
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/fifo"
)

const (
	secretToken = "1j9F5^I0Lr10n*H0Mp2*P^kK@mvv4PR^"
	SUPERADMIN  = "superadmin"
	ADMIN       = "admin"
	USER        = "user"
)

var cacheObj libcache.Cache
var strategy union.Union
var tokenStrategy auth.Strategy

type GoAuthMiddleware struct {
	GoAuth goauth.GoAuth
}

func SetupGoGuardian() {
	cacheObj = libcache.FIFO.New(0)
	cacheObj.SetTTL(time.Minute * 10)
	// basicStrategy := basic.NewCached(validateBasicAuth, cacheObj)
	tokenStrategy = token.New(validateTokenAuth, cacheObj)
	strategy = union.New(tokenStrategy)
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, user, err := strategy.AuthenticateRequest(c.Request)
		if err != nil {
			log.Error("invalid credentials")
			c.JSON(
				http.StatusUnauthorized,
				map[string]interface{}{
					"error": http.StatusText(http.StatusUnauthorized),
				},
			)
			c.Abort()
			return
		}
		c.Set("user", user)
	}
}

// func validateBasicAuth(ctx context.Context, r *http.Request, username, password string) (auth.Info, error) {
// 	userDomain := strings.Split(username, "@")
// 	if len(userDomain) != 2 {
// 		return nil, errors.New("invalid credentials")
// 	}
// 	var domain string
// 	username = userDomain[0]
// 	domain = userDomain[1]
// 	code, res := service.UserServiceGlobal.SignIn(ctx, domain, username, password)
// 	if code != http.StatusOK {
// 		return nil, errors.New("invalid credentials")
// 	}
// 	data, _ := res.(map[string]interface{})
// 	claims, _ := data["data"].(map[string]interface{})
// 	id, _ := claims["user_uuid"].(string)
// 	name, _ := claims["username"].(string)
// 	domainId, _ := claims["domain_uuid"].(string)
// 	domainName, _ := claims["domain_name"].(string)
// 	level, _ := claims["level"].(string)
// 	user := NewGoAuthUser(name, id, nil, nil, domainId, domainName, level, nil)
// 	return user, nil
// }

func validateTokenAuth(ctx context.Context, r *http.Request, tokenString string) (auth.Info, time.Time, error) {
	if tokenString == secretToken {
		id := "2273f762-7ae6-4a0e-a09d-6d5a3c961a50"
		name := "portal"
		domainId := "2273f762-7ae6-4a0e-a09d-6d5a3c961a50"
		domainName := "2273f762-7ae6-4a0e-a09d-6d5a3c961a50"
		level := SUPERADMIN
		user := NewGoAuthUser(name, id, nil, nil, domainId, domainName, level, nil)
		return user, time.Now(), nil
	}
	client, err := goauth.GoAuthClient.CheckTokenInRedis(tokenString)
	if err != nil {
		return nil, time.Time{}, err
	}
	token, err := jwt.Parse(client.JWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		id := client.UserId
		name, _ := claims["username"].(string)
		domainId, _ := claims["domain_uuid"].(string)
		domainName, _ := claims["domain_name"].(string)
		level, _ := claims["level"].(string)
		user := NewGoAuthUser(name, id, nil, nil, domainId, domainName, level, nil)
		return user, time.Now(), nil
	}
	return nil, time.Time{}, errors.New("invalid token")
}

type GoAuthInfo interface {
	auth.Info
	SetDomainId(domainId string)
}

type GoAuthUser struct {
	Name       string          `json:"name"`
	ID         string          `json:"id"`
	Groups     []string        `json:"groups"`
	Extensions auth.Extensions `json:"extensions"`
	DomainId   string          `json:"domain_id"`
	DomainName string          `json:"domain_name"`
	Level      string          `json:"level"`
	Scopes     []string        `json:"scopes"`
}

func NewGoAuthUser(name, id string, groups []string, extensions auth.Extensions, domainId, domainName, level string, scopes []string) GoAuthInfo {
	user := &GoAuthUser{
		DomainId:   domainId,
		DomainName: domainName,
		Level:      level,
		Scopes:     scopes,
	}
	user.Name = name
	user.ID = id
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
	return d.ID
}

func (d *GoAuthUser) SetID(id string) {
	d.ID = id
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
		return user.ID, true
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
	} else {
		return user.DomainId, true
	}
}

func GetUserName(c *gin.Context) (string, bool) {
	user, ok := GetUser(c)
	if !ok {
		return "", false
	} else {
		return user.Name, true
	}
}

func CheckAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userLevel, ok := GetUserLevel(c)
		if !ok || (userLevel != ADMIN && userLevel != SUPERADMIN) {
			c.JSON(
				http.StatusForbidden,
				map[string]interface{}{
					"error": http.StatusText(http.StatusForbidden),
				},
			)
			c.Abort()
			return
		}
	}
}
