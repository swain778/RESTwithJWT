package main

import (
	"auth-jwt/controller"
	"auth-jwt/middleware"
	"auth-jwt/model"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func init() {
	model.SetDBClient()
}

func main() {
	fmt.Println("Welcome to Go authorized with Go")
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Home router",
		})
	})

	r.POST("/signup", controller.Signup)
	r.POST("/login", controller.Login)
	r.GET("/api/v1", middleware.Authorize, controller.Resources)

	r.Run(":5000")
}
