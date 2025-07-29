package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	_ "github.com/AlaxPaulo/api-go/docs" // docs geradas pelo swag
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/AlaxPaulo/api-go/auth"
	"github.com/AlaxPaulo/api-go/handlers"
)

// @title        API-Go Ultrasegura
// @version      1.0
// @description  API em Go com init-token, login e JWT
// @host         localhost:8080
// @BasePath     /
// @schemes      http
// @securityDefinitions.basic BasicAuth   Basic HTTP Authentication

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Aviso: usando vars do SO")
	}

	r := gin.Default()

	// Swagger endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// 1) init-token
	r.GET("/token", auth.GenerateInitToken)

	// 2) login
	r.POST("/login", auth.RequireInitToken(), handlers.Login)

	// 3) rotas protegidas
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
