package auth

import (
	"callcenter-api/common/log"
	"callcenter-api/middleware/auth/goauth"
	"callcenter-api/repository"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/basic"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
	"github.com/shaj13/go-guardian/v2/auth/strategies/union"
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/fifo"
	"github.com/uptrace/bun"
)

var cacheObj libcache.Cache
var strategy union.Union
var tokenStrategy auth.Strategy

type LocalAuthMiddleware struct {
	GoAuth goauth.GoAuth
}

type GoAuthInfo interface {
	auth.Info
	SetDomainId(domainId string)
}

func NewLocalAuthMiddleware() IAuthMiddleware {
	return &LocalAuthMiddleware{}
}

func SetupGoGuardian() {
	cacheObj = libcache.FIFO.New(0)
	cacheObj.SetTTL(time.Minute * 10)
	basicStrategy := basic.NewCached(validateBasicAuth, cacheObj)
	tokenStrategy = token.New(validateTokenAuth, cacheObj)
	strategy = union.New(tokenStrategy, basicStrategy)
}

func (auth *LocalAuthMiddleware) AuthMiddleware() gin.HandlerFunc {
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

type UserAuth struct {
	bun.BaseModel `bun:"v_users,alias:u"`
	UserUuid      string `json:"user_uuid" bun:"user_uuid,pk"`
	DomainUuid    string `json:"domain_id" bun:"domain_uuid"`
	DomainName    string `json:"domain_name" bun:"domain_name"`
	Username      string `json:"username" bun:"username"`
	Password      string `json:"password" bun:"password"`
	Salt          string `json:"salt" bun:"salt"`
	ApiKey        string `json:"api_key" bun:"api_key"`
	UserEnabled   string `json:"user_enabled" bun:"user_enabled"`
	Level         string `json:"level" bun:"level"`
}

func findUserByUsername(ctx context.Context, domainName string, username string) (*UserAuth, error) {
	user := new(UserAuth)
	err := repository.FusionSqlClient.GetDB().NewSelect().
		Model(user).
		ColumnExpr("u.username, u.user_uuid, u.domain_uuid, u.api_key, u.user_enabled, u.password, u.salt, u.level").
		ColumnExpr("d.domain_name").
		Join("inner join v_domains d on u.domain_uuid = d.domain_uuid").
		Where("u.username = ?", username).
		Where("d.domain_name = ?", domainName).
		Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return user, nil
}

func validateBasicAuth(ctx context.Context, r *http.Request, username, password string) (auth.Info, error) {
	userDomain := strings.Split(username, "@")
	if len(userDomain) != 2 {
		log.Error("missing @")
		return nil, errors.New("invalid credentials")
	}
	var domainName string
	username = userDomain[0]
	domainName = userDomain[1]
	user, err := findUserByUsername(ctx, domainName, username)
	if err != nil {
		log.Error(err)
		return nil, errors.New("invalid credentials")
	} else if user == nil {
		log.Error("basic auth not found username")
		return nil, errors.New("invalid credentials")
	}
	passCurrent := user.Password
	hash := md5.New()
	salt := user.Salt
	tmp := salt + password
	_, err = hash.Write([]byte(tmp))
	if err != nil {
		log.Error(err)
		return nil, errors.New("invalid credentials")
	}
	passEncrypted := string(hex.EncodeToString(hash.Sum(nil)))
	if passEncrypted != passCurrent {
		return nil, errors.New("username or password is not valid")
	}
	return NewGoAuthUser(user.Username, user.UserUuid, nil, nil, user.DomainName, user.DomainName, user.Level, nil), nil
}

func validateTokenAuth(ctx context.Context, r *http.Request, tokenString string) (auth.Info, time.Time, error) {
	if tokenString == SECRET_TOKEN {
		id := "2273f762-7ae6-4a0e-a09d-6d5a3c961a50"
		name := "portal"
		domainId := "2273f762-7ae6-4a0e-a09d-6d5a3c961a50"
		domainName := "2273f762-7ae6-4a0e-a09d-6d5a3c961a50"
		level := "superadmin"
		user := NewGoAuthUser(name, id, nil, nil, domainId, domainName, level, nil)
		return user, time.Now(), nil
	}
	client, err := goauth.GoAuthClient.CheckTokenInRedis(ctx, tokenString)
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
