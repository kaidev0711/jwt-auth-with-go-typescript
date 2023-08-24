package app

import "github.com/kaidev0711/jwt-auth-with-go-typescript/backend/controller/users"

func mapUrls() {
	router.POST("/api/register", users.Register)
	router.POST("/api/login", users.Login)
	// router.GET("/api/user", users.Get)
	// router.GET("/api/logout", users.Logout)
}
