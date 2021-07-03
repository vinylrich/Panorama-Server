package handler

import (
	"panorama/server/model"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
)

type RouterHandler struct {
	Hh *gin.Engine
	db model.DBHandler
}

var client = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "",
	DB:       0,
})

func MakeHandler() *RouterHandler {
	r := gin.Default()
	rh := &RouterHandler{
		Hh: r,
		db: model.NewDBHandler(),
	}

	v1 := r.Group("/api/v1")
	{
		user := v1.Group("/user")
		user.POST("signin", rh.signinHandler)
		user.POST("signup", rh.signupHandler)
		post := v1.Group("/post")
		{
			img := post.Group("/img")
			{
				img.POST("upload", rh.upLoadImgHandler)
				img.StaticFS("", gin.Dir("", true))
				img.DELETE("", rh.deleteImgHandler)
			}
			post.GET("/rating", rh.reviewHandler)
			post.GET(":id", rh.getProjectByIdHandler)
			post.GET("", rh.getEntireProjectHandler)
			post.PATCH(":id", rh.modifyProjectHandler)
			post.POST("", rh.upLoadProjectHandler) //contents 동시에 가져와야함
		}
		comment := v1.Group("/comment")
		{
			comment.POST("", rh.uploadCommentHandler)
			comment.GET(":id", rh.getCommentHandler)
		}

	}
	return rh
}
