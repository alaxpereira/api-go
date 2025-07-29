package handlers

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
)

// LoginRequest representa o JSON de entrada
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse representa o JSON de saída
type LoginResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresInH  int    `json:"expires_in_h"`
}

// Login autentica o usuário e retorna JWT
// @Summary     Login
// @Description Valida init-token e usuário/senha, retorna access token
// @Tags        auth
// @Accept      json
// @Produce     json
// @Param       Authorization header string true "Init Token: Bearer <token>"
// @Param       body body LoginRequest true "Credenciais"
// @Success     200 {object} LoginResponse
// @Failure     400 {object} models.ErrorResponse
// @Failure     401 {object} models.ErrorResponse
// @Router      /login [post]
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "parâmetros inválidos"})
		return
	}
	// valida credenciais (exemplo)
	if req.Username != "admin" || req.Password != "1234" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciais inválidas"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "falha ao gerar access token"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken: signed,
		ExpiresInH:  hrs,
	})
}
