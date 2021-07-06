package utils

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Utils interface {
	EncrptPasswd(userpw string) (string, error)
	CompareHash(hashpw, userpw string) bool
	GenerateSessionCookie(username string, client *redis.Client, c http.ResponseWriter) error
	ThrowErr(c *gin.Context, statuscode int, err error)
	Validation(req *http.Request, client *redis.Client) (string, error)
	UploadFile(c *gin.Context, response string) error
}

func ClearSession(c http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(c, cookie)
}
func EncrptPasswd(userpw string) (string, error) {
	hashpw, err := bcrypt.GenerateFromPassword([]byte(userpw), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}
	return string(hashpw), nil
}

func CompareHash(hashpw, userpw string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashpw), []byte(userpw))
	if err == nil {
		return true
	} else {
		return false
	}

}

func GenerateSessionCookie(username string, client *redis.Client, c http.ResponseWriter) error {
	SessionKey := uuid.New().String()
	// Set the token in the cache, along with the user whom it represents
	// The token has an expiry time of 120 seconds
	log.Println(username)

	err := client.Set(SessionKey, username, 1800*time.Second).Err()

	if err != nil {
		return err
	}

	http.SetCookie(c, &http.Cookie{
		Name:    "session_id",
		Value:   SessionKey,
		Expires: time.Now().Add(60 * time.Minute),
		Path:    "/",
	})
	return nil
}

//if result is true, create cookie
func SigninValidation(req *http.Request, client *redis.Client) (bool, error) {

	sessionKey, err := req.Cookie("session_id")
	if err != nil {
		if err == http.ErrNoCookie {
			return false, nil
		}
		// For any other type of error, return a bad request status
		return true, err
	}
	response, err := client.Get(sessionKey.Value).Result()
	if response == "" {
		// If the session token is not present in cache, return an unauthorized error
		return false, nil
	}
	if err != nil {
		return true, err
	}

	return true, nil
}
func Validation(req *http.Request, client *redis.Client) (string, error) {

	sessionKey, err := req.Cookie("session_id")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", err
		}
		// For any other type of error, return a bad request status
		return "", err
	}
	response, err := client.Get(sessionKey.Value).Result()
	if response == "" {
		// If the session token is not present in cache, return an unauthorized error
		err := errors.New("session token is not present in cache")
		return "", err
	}
	if err != nil {
		return "", err
	}

	return response, nil
}

func UploadFile(c *gin.Context, response string) error {
	header, err := c.FormFile("upload_file")
	uploadfile, _ := header.Open()
	if err != nil {
		return err
	}
	defer uploadfile.Close()

	dirname := "./public/imgpath/" + response
	os.MkdirAll(dirname, 0777)
	filepath := fmt.Sprintf("%s/%s/%s", "public/imgpath", response, header.Filename) //imgpath/username/filename
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	io.Copy(file, uploadfile)

	return nil
}
