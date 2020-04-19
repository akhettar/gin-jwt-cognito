# Gin Cognito JWT Authentication Middleware 
![Master CI](https://github.com/akhettar/gin-jwt-cognito/workflows/Master%20CI/badge.svg)
[![GoDoc](https://godoc.org/github.com/akhettar/gin-jwt-cognito?status.svg)](https://godoc.org/github.com/akhettar/gin-jwt-cognito)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/034105613f514f4b94c52c62c323101b)](https://www.codacy.com/manual/akhettar/gin-jwt-cognito?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=akhettar/gin-jwt-cognito&amp;utm_campaign=Badge_Grade)

![Gin](gin.png)


This is a JWT auth [Gin Middleware](https://github.com/gin-gonic/gin) to validate JWT token issued by [AWS Cognito identity manager](https://aws.amazon.com/cognito/). The implementation of this middleware is based 
on the [AWS documentation on how to verify the JWT token](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html)


Here is an example of how can this be invoked. It should be attached to all endpoint you would want to authenticate against the user.

```go

package main

import (
	"github.com/gin-gonic/gin"
    "github.com/akhettar/gin-jwt-cognito"
)

func main() {

	// Creates a gin router with default middleware:
	router := gin.Default()

	// Create Cognito JWT auth middleware and set it  in all authenticated endpoints
	mw, err := jwt.AuthJWTMiddleware("<some_iss>", "<some_userpool_id>", "region")
	if err != nil {
		panic(err)
	}

	router.GET("/someGet", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})
	router.POST("/somePost", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})
	router.PUT("/somePut", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})

	// By default it serves on :8080 unless a
	// PORT environment variable was defined.
	router.Run()
}

```

# License
[MIT](LICENSE)