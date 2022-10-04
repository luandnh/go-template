package auth

import (
	"callcenter-api/common/log"

	"net/http"

	"github.com/gin-gonic/gin"
)

type GatewayAuthMiddleware struct {
}

func NewGatewayAuthMiddleware() IAuthMiddleware {
	return &GatewayAuthMiddleware{}
}

func (mdw *GatewayAuthMiddleware) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := ParseHeaderToUser(c)
		if len(user.GetID()) < 1 {
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

func ParseHeaderToUser(c *gin.Context) *GoAuthUser {
	return &GoAuthUser{
		DomainId:   c.Request.Header.Get("X-Tenant-Id"),
		DomainName: c.Request.Header.Get("X-Tenant-Name"),
		Id:         c.Request.Header.Get("X-User-Id"),
		Level:      c.Request.Header.Get("X-User-Level"),
		Name:       c.Request.Header.Get("X-User-Name"),
	}
}
