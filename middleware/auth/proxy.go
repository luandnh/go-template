package auth

import (
	"callcenter-api/common/log"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type GoAuthMiddleware struct {
	authUrl string
}

func NewGoAuthMiddleware(authUrl string) IAuthMiddleware {
	return &GoAuthMiddleware{
		authUrl: authUrl,
	}
}

func (mdw *GoAuthMiddleware) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization")
		if len(token) < 1 {
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
		GoAuthUser, err := mdw.postToAuthAPI(token)
		if err != nil {
			log.Error(err)
			c.JSON(
				http.StatusUnauthorized,
				map[string]interface{}{
					"error": http.StatusText(http.StatusUnauthorized),
				},
			)
			c.Abort()
			return
		}
		c.Set("user", GoAuthUser)
	}
}

func (mdw *GoAuthMiddleware) postToAuthAPI(token string) (*GoAuthUser, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	req, err := http.NewRequest("POST", mdw.authUrl, nil)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	//http fix request not close tcp
	req.Header.Set("Connection", "close")
	req.Close = true
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	client.Transport = tr
	res, err := client.Do(req)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusAccepted {
		return nil, errors.New("unauthorized")
	}
	GoAuthUser := new(GoAuthUser)
	err = json.NewDecoder(res.Body).Decode(GoAuthUser)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return GoAuthUser, nil
}
