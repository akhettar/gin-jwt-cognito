# Gin Cognito JWT Authentication Middleware 
![Master CI](https://github.com/akhettar/gin-jwt-cognito/workflows/Master%20CI/badge.svg)
[![GoDoc](https://godoc.org/github.com/devopsfaith/krakend?)

![Gin](gin.png)


This is a JWT auth [Gin Middleware](https://github.com/gin-gonic/gin) to validate JWT token issued by [AWS Cognito identity manager](https://aws.amazon.com/cognito/)


Here is an example of how can this be invoked. It should be attached to all endpoint you would want to authenticate against the user.

```go

package main

import (
    "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
    "github.com/akhettar/gin-jwt-cognito"
)

// Custom Error response
type ErrorResponse struct {
	Message string `json:"message"`
	Code    int    `json:code`
}

func main() {

	// Creates a gin router with default middleware:
	// logger and recovery (crash-free) middleware
	router := gin.Default()
    
    mw := jwt.GinJWTMiddleware()



	router.GET("/someGet", getting)
	router.POST("/somePost", posting)
	router.PUT("/somePut", putting)
	
	// By default it serves on :8080 unless a
	// PORT environment variable was defined.
	router.Run()
	// router.Run(":3000") for a hard coded port
}


// Registers all the routes
func  {

	// Create router
	router := gin.New()
	router.Use(logger.Logger())
	router.Use(gin.Recovery())

	router.GET("/tags", jwt.GinJWTMiddleware().MiddlewareFunc(), handler.GetAllTags)
	router.GET("/tags/:id", jwt.GinJWTMiddleware().MiddlewareFunc(), handler.GetTag)
	router.DELETE("/tags/:id", jwt.GinJWTMiddleware().MiddlewareFunc(), handler.DeleteTag)
	router.GET("/health", handler.Health)
	router.POST("/tags", jwt.GinJWTMiddleware().MiddlewareFunc(), handler.CreateTag)
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return router
}

```
