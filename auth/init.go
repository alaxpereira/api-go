package auth

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// GenerateInitToken exige agentId+agentSecret antes de emitir o init token
func GenerateInitToken(c *gin.Context) {
	id, secret, ok := c.Request.BasicAuth()
	if !ok ||
		id != os.Getenv("AGENT_ID") ||
		secret != os.Getenv("AGENT_SECRET") {
		c.Header("WWW-Authenticate", `Basic realm="API Init"`)
		c.AbortWithStatusJSON(http.StatusUnauthorized,
			gin.H{"error": "credenciais do agente inválidas"})
		return
	}

	mins, err := strconv.Atoi(os.Getenv("INIT_TOKEN_EXPIRE_MINUTES"))
	if err != nil {
		mins = 5
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"init": true,
		"iat":  now.Unix(),
		"exp":  now.Add(time.Duration(mins) * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": "falha ao gerar init token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"init_token":     signed,
		"expires_in_min": mins,
	})
}
