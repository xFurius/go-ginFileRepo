package controllers

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

// upload
func Upload(ctx *gin.Context) {
	file, err := ctx.FormFile("test")
	if err != nil {
		log.Fatal(err)
	}
	source := rand.NewSource(time.Now().Unix())
	r := source.Int63()
	fmt.Println(int(r))

	ext := strings.Split(file.Filename, ".")[len(strings.Split(file.Filename, "."))-1]
	fmt.Println(ext)

	replacer := strings.NewReplacer(" ", "_", "(", "_", ")", "_", ".", "_")
	fileName := replacer.Replace(file.Filename)
	filename := fileName + strconv.Itoa(int(r)) + "." + ext

	uploadDate := time.Now().Format("2006-01-02 3:04:05 pm")
	fmt.Println(uploadDate)

	FilesCol.InsertOne(context.Background(), bson.M{"E-mail": GetEmailFromToken(ctx), "FileName": filename, "UploadDate": uploadDate, "FileSize": file.Size, "FileType": strings.Split(filename, ".")[1]})
	err = ctx.SaveUploadedFile(file, "./files/"+filename)
	fmt.Println(err)
}

// file deletion
func Delete(ctx *gin.Context) {
	res, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(res))

	tempR := strings.ReplaceAll(string(res), "file=", "")
	files := strings.Split(tempR, "&")
	fmt.Println(files)

	for _, v := range files {
		if _, err = FilesCol.DeleteOne(context.Background(), bson.D{{Key: "FileName", Value: v}}); err != nil {
			fmt.Println(err)
		}
		path := "./files/" + v
		os.Remove(path)
	}

	location := url.URL{Path: "/user/viewFiles"}
	ctx.Redirect(http.StatusFound, location.RequestURI())

}

// file download
// one file at a time for now
func Download(ctx *gin.Context) {
	res, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		log.Fatal(err)
	}
	res = res[5:]
	fmt.Println(string(res))

	ctx.FileAttachment("./files/"+string(res), string(res))
}
