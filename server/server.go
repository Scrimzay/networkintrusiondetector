package server

import (
	"github.com/gin-gonic/gin"
)

func RunServer() {
	r := gin.Default()

	r.GET("/", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"message": "Hello"})
	})

	r.POST("/login", func(ctx *gin.Context) {
        var input struct {
            Username string `json:"username"`
            Password string `json:"password"`
        }
        if err := ctx.ShouldBindJSON(&input); err != nil {
            ctx.JSON(400, gin.H{"error": "Invalid input"})
            return
        }
        ctx.JSON(200, gin.H{"message": "Login attempt received", "username": input.Username, "password": input.Password})
    })

	r.Run(":8080")
}