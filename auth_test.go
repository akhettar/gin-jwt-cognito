package jwt

import (
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	ExpiredCognitoToken = "eyJraWQiOiJsY2ZiTlVjNm9CYVlrMTlpRGhsVnI2OUk2ZTZcL3hCQTAzakk5SkhiM2lmST0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkZDAzODg3OS0xMTA2LTRkZjMtOTFhZS0wM2UwYjc5Zjc4NDMiLCJldmVudF9pZCI6ImY4ZTQ4NGI0LWVmMzEtNDIxNy05NjRmLTNhZWZkM2NlNWZjNSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1NjM4NzEwMjQsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS13ZXN0LTIuYW1hem9uYXdzLmNvbVwvZXUtd2VzdC0yX25VV05zeWx6VCIsImV4cCI6MTU2Mzg3NDYyNCwiaWF0IjoxNTYzODcxMDI0LCJqdGkiOiJhOGYwMmJjMC0xZTM0LTQxMmItYjE3Yi1hMTAyYWM3YTIxNjkiLCJjbGllbnRfaWQiOiI0MjNhNWNjNnRqNWkzYW1kbWgwYXIycmszIiwidXNlcm5hbWUiOiIzYmI3MWUxNS00NjQ5LTQ0MjktYjE3MS1iMjEwNTlhYmQwZjAifQ.KnRZ6gEVwZNRPmULRk9VA7HlhAViOnwMPezakuBHXwNHFieThlJR6y8uMhcVS4bm0Du55PkIjVWkFgl9G1aiRgtd2k6vVtJHw_PPoe6VbvKDuus3ZSyu9NCD4DBF10_dEsEw3CibfrAxislw0-AEGZT_DegZgHWV5rzMBFZYeOJ7ptxpyykQOhkL7NtN1kB7BwBIUKMGw7mUAOGkPXC5RuKNPbUj4FFt-OmQX4-mDYNeQY6zkLrLt9eizf4N1CKR1WjMdeBHUrIgfrXuY1ZGrD9ZQGgEqzT2wZ9ZO3lNtBm1t65sQvvJTfTDwQb1z-dV1yXCravMd28g9fC8Jda9XQ"
	CheckMark           = "\u2713"
	BallotX             = "\u2717"
)

func Test_MissingAuthorizationHeader(t *testing.T) {
	t.Logf("Given the authorization header is not set")
	{
		middleware := AuthMiddleware{UserPoolID: "some_user_id_pool", Region: "some_region"}
		emptyMap := http.Header{}
		request := http.Request{Header: emptyMap}
		ctx := gin.Context{Request: &request}
		_, err := middleware.jwtFromHeader(&ctx, AuthorizationHeader)
		assert.NotNil(t, err)
		assert.Equal(t, "auth header empty", err.Error())
		expectedErrorMessage := "auth header empty"
		if expectedErrorMessage == err.Error() {
			t.Logf("\t\t The error message should have been \"%s\". %v", err.Error(), CheckMark)
		} else {
			t.Errorf("\t\t The error message should have been \"%s\". %v", err.Error(), CheckMark)
		}
	}
}

func Test_CognitoTokenExpiredShouldResultInUnauthorisedError(t *testing.T) {
	t.Logf("Given the middleWareImpl method has been invoked with  an expired token")
	{
		middleware := &AuthMiddleware{UserPoolID: "some_user_id_pool", Region: "some_region"}

		router := ginHandler(middleware)

		// Perform a GET request with that handler.
		response := performRequest(router, "GET", "/auth/list", ExpiredCognitoToken)

		if response.Code == http.StatusUnauthorized {
			t.Logf("\t\t The http response status code should be %d. %v", response.Code, CheckMark)
		} else {
			t.Errorf("\t\t The http response status code should be %d but got %d. %v", http.StatusUnauthorized, response.Code, BallotX)
		}

	}
}

func performRequest(r http.Handler, method, path string, token string) *httptest.ResponseRecorder {
	headers := http.Header{}
	headers.Add(AuthorizationHeader, token)
	req, _ := http.NewRequest(method, path, nil)
	req.Header = headers

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Helper for Handler
func ginHandler(auth *AuthMiddleware) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	group := r.Group("/auth")
	group.Use(auth.MiddlewareFunc())
	{
		group.GET("/list", testHandler)
	}
	return r
}

func testHandler(c *gin.Context) {
	c.JSON(200, "success")
}
