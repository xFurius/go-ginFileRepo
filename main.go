package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func init() {
	godotenv.Load(".env")
}

// func signUp(c *gin.Context) {
// 	c.HTML(http.StatusOK, "signUp.html", gin.H{
// 		"title": "Main website",
// 	})
// }

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

	router.GET("/dbtest", func(ctx *gin.Context) {
		_, err := cTest.InsertOne(context.Background(), bson.M{"Username": "test", "E-mail": "email", "Password": "password"})
		if err != nil {
			fmt.Println(err)
		}
	})

	// router.GET("/signUp", signUp)

	router.Run()
}

// require('dotenv').config();

// process.env.USER_ID; // "239482"
// process.env.USER_KEY; // "foobar"   <- js
// process.env.NODE_ENV; // "development"
