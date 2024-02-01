package controller

import (
	"auth-jwt/model"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func Signup(c *gin.Context) {
	var reqUser model.User

	if err := c.ShouldBind(&reqUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	var dbUser model.User
	model.DB.Where("email=?", reqUser.Email).First(&dbUser)
	if dbUser.Email != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "user with email found, login",
		})
		return
	}

	//Harsh user password
	err := reqUser.GeneratePasswordHarsh()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to harsh password",
		})
		return
	}

	//Add user into the database
	res := model.DB.Create(&reqUser)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create user",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user": reqUser,
	})
}

func Login(c *gin.Context) {
	var reqUser model.User
	if err := c.ShouldBind(&reqUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	var dbUser model.User
	model.DB.Where("email=?", reqUser.Email).First(&dbUser)

	if dbUser.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	if dbUser.CheckPasswordHarsh(reqUser.Password) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": dbUser.Email,
			"exp": time.Now().Add(time.Minute * 10).Unix(),
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
		c.JSON(http.StatusOK, gin.H{
			"user": dbUser,
		})
	} else {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Invalid email or password",
		})
	}
}

func Resources(c *gin.Context) {
	var users []model.User
	res := model.DB.Find(&users)
	if res.Error != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "error fetching users",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}
