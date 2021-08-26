package utils

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}
type AccessDetails struct {
	AccessUuid string
	UserId     uint64
}

var AccessToken = []byte(os.Getenv("ACCESS_SECRET"))
var RefreshToken = []byte(os.Getenv("REFRESH_SECRET"))

type Utils interface {
	EncrptPasswd(userpw string) (string, error)
	CompareHash(hashpw, userpw string) bool
	GenerateToken(username string, client *redis.Client, c *http.ResponseWriter) error
	ThrowErr(c *gin.Context, statuscode int, err error)
	Validation(req *http.Request, client *redis.Client) (string, error)
	UploadFile(c *gin.Context, response string) error
}

func ClearSession(c http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session_id",
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

//Create Token
func GenerateToken(username string) (*TokenDetails, error) {
	td := &TokenDetails{}

	td.AtExpires = time.Now().Add(15 * time.Minute).Unix()
	td.AccessUuid = uuid.New().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.New().String()

	var err error

	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["username"] = username
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	td.AccessToken, err = at.SignedString(AccessToken)
	if err != nil {
		return nil, err
	}

	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["username"] = username
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)

	td.RefreshToken, err = rt.SignedString(RefreshToken)
	if err != nil {
		return nil, err
	}

	return td, nil
}

//saving session
func CreateSession(username string, td *TokenDetails, client *redis.Client) error {
	at := time.Unix(td.AtExpires, 0)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(td.AccessUuid, username, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(td.RefreshUuid, username, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

//if result is true, create cookie
// func InitValidation(req *http.Request, client *redis.Client) (bool, error) {

// 	sessionKey, err := req.Cookie("session_id")
// 	if err != nil {
// 		if err == http.ErrNoCookie {
// 			return false, nil
// 		}
// 		// For any other type of error, return a bad request status
// 		return true, err
// 	}
// 	response, err := client.Get(sessionKey.Value).Result()
// 	if response == "" {
// 		// If the session token is not present in cache, return an unauthorized error
// 		return false, nil
// 	}
// 	if err != nil {
// 		return true, err
// 	}

// 	return true, nil
// }

// func VerifyToken(req *http.Request, client *redis.Client) (string, error) {
// 	sessionKey, err := req.Cookie("session_id")
// 	if err != nil {
// 		if err == http.ErrNoCookie {
// 			return "", err
// 		}
// 		// For any other type of error, return a bad request status
// 		return "", err
// 	}
// 	response, err := client.Get(sessionKey.Value).Result()
// 	if response == "" {
// 		// If the session token is not present in cache, return an unauthorized error
// 		err := errors.New("session token is not present in cache")
// 		return "", err
// 	}
// 	if err != nil {
// 		return "", err
// 	}

// 	return response, nil
// }

//Verify Token
func VerifyToken(req *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(req)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

//Get Token
func ExtractToken(req *http.Request) string {
	bearToken := req.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func TokenValid(req *http.Request) error {
	token, err := VerifyToken(req)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		errors.New("Token is Unavailable")
		return err
	}
	return nil
}
func ExtractTokenMetadata(req *http.Request) (*AccessDetails, error) {
	token, err := VerifyToken(req)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	return nil, err
}

func GetAuth(authD *AccessDetails, client *redis.Client) (string, error) {
	username, err := client.Get(authD.AccessUuid).Result()
	if err != nil {
		return "", err
	}
	return username, nil
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
