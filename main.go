package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
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
		log.Fatal(err)
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
			log.Fatal(err)
		}
		fmt.Println(data)

		//TODO:
		//		email regex
		//		email verification / email cant be a duplicate
		//		access tokens

		cost, _ := strconv.Atoi(os.Getenv("COST"))
		hash, err := bcrypt.GenerateFromPassword([]byte(data.Password), cost)
		if err != nil {
			log.Fatal(err)
		}

		res := cTest.FindOne(context.Background(), bson.M{"E-mail": data.Email})
		if res.Err() == nil {
			ctx.Status(http.StatusForbidden)
			return
		}

		_, err = cTest.InsertOne(context.Background(), bson.M{"E-mail": data.Email, "Password": hash})
		if err != nil {
			fmt.Println(err)
		}

		// err = bcrypt.CompareHashAndPassword(hash, []byte(data.Password))
		// if err != nil {
		// 	fmt.Println(err)
		// }
	})

	router.Run()
}
