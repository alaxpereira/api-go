package handlers

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest,
			gin.H{"error": "parâmetros inválidos"})
		return
	}
	// TODO: substitua por validação real no banco
	if req.Username != "admin" || req.Password != "1234" {
		c.JSON(http.StatusUnauthorized,
			gin.H{"error": "credenciais inválidas"})
		return
	}

	hrs, err := strconv.Atoi(os.Getenv("JWT_EXPIRE_HOURS"))
	if err != nil {
		hrs = 24
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   req.Username,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(hrs) * time.Hour)),
		Issuer:    "api-go",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": "falha ao gerar access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": signed,
		"expires_in_h": hrs,
	})
}
