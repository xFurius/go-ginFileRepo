package controllers

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var UsersCol *mongo.Collection
var FilesCol *mongo.Collection

// database connection
func ConnectDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(client)

	UsersCol = client.Database("go-ginFileRepo").Collection("Users")
	FilesCol = client.Database("go-ginFileRepo").Collection("Files")
}

// displaying files uploaded by logged in user
func ViewUserFileData(ctx *gin.Context) ([]string, map[string][]string) {
	cursor, err := FilesCol.Find(context.Background(), bson.D{{Key: "E-mail", Value: GetEmailFromToken(ctx)}})
	if err != nil {
		fmt.Println(err)
	}

	var res []bson.M
	if err = cursor.All(context.Background(), &res); err != nil {
		fmt.Println(err)
	}

	files := make([]string, 0)
	fileData := make(map[string][]string, 0)
	for _, v := range res {
		files = append(files, v["FileName"].(string))
		temp := []string{
			// TODO: convert btyes to kb/mb/gb
			v["UploadDate"].(string), fmt.Sprint(v["FileSize"].(int64)), v["FileType"].(string),
		}
		fileData[v["FileName"].(string)] = temp
	}

	return files, fileData
}
