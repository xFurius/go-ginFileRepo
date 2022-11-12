package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func init() {
	godotenv.Load(".env")
}

func connectDB() *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatalln(err)
	}
	return c
}

func main() {
	client := connectDB()
	cTest := client.Database("go-ginFileRepo").Collection("Users")

	router := gin.Default()
	router.LoadHTMLGlob("./html/*")

	router.GET("/signUp", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "signUp.html", nil)
	})

	router.POST("/signUp", func(ctx *gin.Context) {
		var data User
		err := ctx.BindJSON(&data)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(data)

		//TODO: password hashing
		//		email regex
		//		email verification
		//		access tokens

		_, err = cTest.InsertOne(context.Background(), bson.M{"Username": data.Username, "E-mail": data.Email, "Password": data.Password})
		if err != nil {
			fmt.Println(err)
		}
	})

	router.Run()
}
