// main_test.go
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/AlaxPaulo/api-go/auth"
	"github.com/AlaxPaulo/api-go/handlers"
	"github.com/stretchr/testify/assert"
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/token", auth.GenerateInitToken)
	r.POST("/login", auth.RequireInitToken(), handlers.Login)
	api := r.Group("/api", auth.RequireUserToken())
	api.GET("/ping", func(c *gin.Context) {
		user := c.GetString("userID")
		c.JSON(200, gin.H{"pong": "E aí, " + user + "!"})
	})
	return r
}

func TestTokenEndpoint(t *testing.T) {
	router := setupRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/token", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp["token"])
}

func TestLogin_MissingInitToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("JWT_EXPIRE_HOURS", "1")
	router := setupRouter()
	body := handlers.LoginRequest{Username: "admin", Password: "1234"}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_ValidInitTokenAndCredentials(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("JWT_EXPIRE_HOURS", "1")
	router := setupRouter()

	// Get init-token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/token", nil)
	router.ServeHTTP(w, req)
	var tokenResp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &tokenResp)
	initToken := tokenResp["token"]

	body := handlers.LoginRequest{Username: "admin", Password: "1234"}
	b, _ := json.Marshal(body)
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+initToken)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestPing_MissingJWT(t *testing.T) {
	router := setupRouter()
	req, _ := http.NewRequest("GET", "/api/ping", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPing_ValidJWT(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("JWT_EXPIRE_HOURS", "1")
	router := setupRouter()

	// Get init-token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/token", nil)
	router.ServeHTTP(w, req)
	var tokenResp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &tokenResp)
	initToken := tokenResp["token"]

	// Login to get JWT
	body := handlers.LoginRequest{Username: "admin", Password: "1234"}
	b, _ := json.Marshal(body)
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+initToken)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var loginResp handlers.LoginResponse
	_ = json.Unmarshal(w.Body.Bytes(), &loginResp)
	jwtToken := loginResp.AccessToken

	// Call /api/ping with JWT
	req, _ = http.NewRequest("GET", "/api/ping", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["pong"], "admin")
}