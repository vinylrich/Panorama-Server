package handler

import (
	"errors"
	"log"
	"net/http"
	"panorama/server/model"
	"panorama/server/utils"
	"strconv"

	"github.com/gin-gonic/gin"
)

var err error

// Summary Signin
// Router api/v1/signin [post]
func (rh *RouterHandler) signinHandler(c *gin.Context) {
	var user model.User
	if err = c.ShouldBindJSON(&user); err != nil {
		// If err occurs BINDING(ENCODING) user err, return serverError
		utils.ThrowErr(c, http.StatusBadRequest, err)
		return
	}

	if user.Username == "" {
		// If binded username is empty, return partialcontent
		err = errors.New("username is should'nt be empty")
		utils.ThrowErr(c, http.StatusPartialContent, err)
		return
	}

	isuser, err := rh.db.SigninIsUser(user)
	if err != nil {
		// If err occurs in calling SignInIsUser, return ISE
		utils.ThrowErr(c, http.StatusPartialContent, err)
		return
	}
	if !isuser {
		// If cant find User, return Unauthorized?
		err = errors.New("user not Found")
		utils.ThrowErr(c, http.StatusUnauthorized, err)
		return
	}
	var httpwriter http.ResponseWriter = c.Writer

	err = utils.GenerateSessionCookie(user.Username, client, httpwriter)

	if err != nil {
		//If err occurs in generating sessioncookie, return ISE
		utils.ThrowErr(c, http.StatusInternalServerError, err)
		return
	}
	//Signin successfully
	err = errors.New("login successfully")
	utils.ThrowErr(c, http.StatusOK, err)
}

// Summary Sign up
// Router api/v1/signup [post]
func (rh *RouterHandler) signupHandler(c *gin.Context) {
	log.Print("call signup handler")
	var user model.User

	if err := c.ShouldBindJSON(&user); err != nil {
		// If err occurs BINDING(ENCODING) user err, return serverError
		utils.ThrowErr(c, http.StatusInternalServerError, err)
		return
	}
	if user.Username == "" {
		// If binded username is empty, return partialcontent
		err = errors.New("username is empty")
		utils.ThrowErr(c, http.StatusPartialContent, err)
		return
	}
	hashpwd, err := utils.EncrptPasswd(user.Password)
	if err != nil {
		//If err occurs in encrpt passwd, return ISE
		utils.ThrowErr(c, http.StatusInternalServerError, err)
		return
	}
	user.Password = hashpwd

	isuser, err := rh.db.SignupIsUser(user)
	if err != nil {
		//If err occurs in calling SignupIsUser, return ISE
		utils.ThrowErr(c, http.StatusInternalServerError, err)
		return
	}
	if isuser {
		//If user already exist, return partialcontent
		err = errors.New("user alreay exist")
		utils.ThrowErr(c, http.StatusPartialContent, err)
		return

	}

	err = rh.db.AddUser(&user)
	if err != nil {
		//If err occurs in Adding User, return partialcontent
		utils.ThrowErr(c, http.StatusPartialContent, err)
		return
	}
	//Signup successfully
	err = errors.New("signup successfully")
	utils.ThrowErr(c, http.StatusCreated, err)
}

// Summary upload img
// Description Upload img to public folder to use fileserver
// Router api/v1/post/img [get]
func (rh *RouterHandler) upLoadImgHandler(c *gin.Context) {

	response, err := utils.Validation(c.Request, client)
	if response == "" {
		utils.ThrowErr(c, http.StatusUnauthorized, err)
	}
	if err != nil {
		if err == http.ErrNoCookie {
			utils.ThrowErr(c, http.StatusUnauthorized, err)
			return
		}
		utils.ThrowErr(c, http.StatusInternalServerError, err)
		return
	}

	err = utils.UploadFile(c, response)
	if err != nil {
		utils.ThrowErr(c, http.StatusInternalServerError, err)
	}
	err = errors.New("successfully Upload")
	utils.ThrowErr(c, http.StatusOK, err)

}

// Summary get post contents
// Router api/v1/post/content [get]
func (rh *RouterHandler) getPostHandler(c *gin.Context) {

	response, err := utils.Validation(c.Request, client)
	if response == "" {
		utils.ThrowErr(c, http.StatusUnauthorized, err)
		return
	}
	if err != nil {
		if err == http.ErrNoCookie {
			utils.ThrowErr(c, http.StatusUnauthorized, err)
			return
		}
		utils.ThrowErr(c, http.StatusInternalServerError, err)
		return
	}

	id := c.Query("id")
	postid, _ := strconv.Atoi(id)

	post, err := rh.db.GetbyIdPost(postid)

	log.Println(post)

}

func (rh *RouterHandler) getEntirePostHandler(c *gin.Context) {
	posts, err := rh.db.GetPost()
	if err != nil {
		if posts != nil {
			errors.New("empty contents")
			utils.ThrowErr(c, http.StatusPartialContent, err)
		}
		utils.ThrowErr(c, http.StatusInternalServerError, err)
	}
	posts.
		c.JSON(200, gin.H{})
}

// Summary upload post
// Router api/v1/post [post]
func (rh *RouterHandler) upLoadPostHandler(c *gin.Context) {
	var post model.Post

	response, err := utils.Validation(c.Request, client)
	if response == "" {
		utils.ThrowErr(c, http.StatusUnauthorized, err)
	}
	if err != nil {
		if err == http.ErrNoCookie {
			utils.ThrowErr(c, http.StatusUnauthorized, err)
			return
		}
		utils.ThrowErr(c, http.StatusInternalServerError, err)
		return
	}

	if err := c.ShouldBindJSON(&post); err != nil {
		utils.ThrowErr(c, http.StatusInternalServerError, err)
		return
	}
	if post.ProjectTitle == "" {
		// If binded username is empty, return partialcontent
		err = errors.New("post title empty")
		utils.ThrowErr(c, http.StatusPartialContent, err)
		return
	}
	if len(post.Contents) < 20 {
		err = errors.New("post contents len should belong then 20")
		utils.ThrowErr(c, http.StatusPartialContent, err)
		return
	}
	rh.db.UploadPost(&post)
}

// Summary update post contents
// Router api/v1/post [patch]
func (rh *RouterHandler) modifyPostHandler(c *gin.Context) {

}

// Summary delete img temporary
// Router api/v1/img [delete]
func (rh *RouterHandler) deleteImgHandler(c *gin.Context) {

}

func (rh *RouterHandler) Close() {
	rh.db.Close()
	client.Close()
}
