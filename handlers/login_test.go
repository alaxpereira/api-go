// login_test.go
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/login", Login)
	return r
}

func TestLogin_ValidCredentials(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("JWT_EXPIRE_HOURS", "1")
	router := setupRouter()

	body := LoginRequest{Username: "admin", Password: "1234"}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, 1, resp.ExpiresInH)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("JWT_EXPIRE_HOURS", "1")
	router := setupRouter()

	body := LoginRequest{Username: "admin", Password: "wrong"}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_MissingFields(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("JWT_EXPIRE_HOURS", "1")
	router := setupRouter()

	body := map[string]string{"username": "admin"}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_JWTError(t *testing.T) {
	os.Setenv("JWT_SECRET", "")
	os.Setenv("JWT_EXPIRE_HOURS", "1")
	router := setupRouter()

	body := LoginRequest{Username: "admin", Password: "1234"}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}