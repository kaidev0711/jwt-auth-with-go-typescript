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

func Get(c *gin.Context) {
	cookie, err := c.Cookie("jwt")
	if err != nil {
		getErr := errors.NewInternalServerError("could not cookie")
		c.JSON(getErr.Status, getErr)
		return
	}
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		restErr := errors.NewInternalServerError("error parsing cookie")
		c.JSON(restErr.Status, restErr)
		return
	}
	claims := token.Claims.(*jwt.StandardClaims)
	issuer, err := strconv.ParseInt(claims.Issuer, 10, 64)
	if err != nil {
		restErr := errors.NewInternalServerError("user id should be number")
		c.JSON(restErr.Status, restErr)
		return
	}
	result, restErr := services.GetUserByID(issuer)
	if restErr != nil {
		c.JSON(restErr.Status, restErr)
		return
	}
	c.JSON(http.StatusOK, result)
}

func Logout(c *gin.Context) {
	c.SetCookie("jwt", "", -1, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "success",
	})
}
