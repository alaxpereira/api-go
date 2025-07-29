package auth

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// RequireInitToken protege o /login
func RequireInitToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		hdr := c.GetHeader("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "init token não fornecido"})
			return
		}
		tokenStr := strings.TrimPrefix(hdr, "Bearer ")
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		if err != nil || !tok.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "init token inválido"})
			return
		}
		claims := tok.Claims.(jwt.MapClaims)
		if claims["init"] != true {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "token não é init token"})
			return
		}
		c.Next()
	}
}

// RequireUserToken protege as rotas /api/**
func RequireUserToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		hdr := c.GetHeader("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "access token não fornecido"})
			return
		}
		tokenStr := strings.TrimPrefix(hdr, "Bearer ")
		tok, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{},
			func(t *jwt.Token) (interface{}, error) {
				return []byte(os.Getenv("JWT_SECRET")), nil
			})
		if err != nil || !tok.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "access token inválido"})
			return
		}
		claims := tok.Claims.(*jwt.RegisteredClaims)
		c.Set("userID", claims.Subject)
		c.Next()
	}
}
