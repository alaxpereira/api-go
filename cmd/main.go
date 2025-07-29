package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/AlaxPaulo/api-go/auth"
	"github.com/AlaxPaulo/api-go/handlers"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Aviso: não achei .env, usando env do sistema")
	}

	r := gin.Default()

	// 1) GET /token (BasicAuth)
	r.GET("/token", auth.GenerateInitToken)

	// 2) POST /login (RequireInitToken)
	r.POST("/login", auth.RequireInitToken(), handlers.Login)

	// 3) rotas protegidas (RequireUserToken)
	api := r.Group("/api", auth.RequireUserToken())
	api.GET("/ping", func(c *gin.Context) {
		user := c.GetString("userID")
		c.JSON(200, gin.H{"pong": "E aí, " + user + "!"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
