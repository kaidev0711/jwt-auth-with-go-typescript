package users

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/kaidev0711/jwt-auth-with-go-typescript/backend/domain/users"
	"github.com/kaidev0711/jwt-auth-with-go-typescript/backend/services"
	"github.com/kaidev0711/jwt-auth-with-go-typescript/backend/utils/errors"
)

const (
	SecretKey = "kaidev0711"
)

func Register(c *gin.Context) {
	var user users.User

	if err := c.ShouldBindJSON(&user); err != nil {
		err := errors.NewBadRequestError("Invalid json body")
		c.JSON(err.Status, err)
		return
	}
	result, saveErr := services.CreateUser(user)
	if saveErr != nil {
		c.JSON(saveErr.Status, saveErr)
		return
	}
	c.JSON(http.StatusOK, result)
}

func Login(c *gin.Context) {
	var user users.User
	if err := c.ShouldBindJSON(&user); err != nil {
		err := errors.NewBadRequestError("Invalid json ")
		c.JSON(err.Status, err)
		return
	}

	result, getErr := services.GetUser(user)
	if getErr != nil {
		c.JSON(getErr.Status, getErr)
		return
	}
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(result.ID)),
		ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
	})
	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		err := errors.NewInternalServerError("login failed")
		c.JSON(err.Status, err)
		return
	}
	c.SetCookie("jwt", token, 3600, "/", "localhost", false, true)
	c.JSON(http.StatusOK, result)
}
