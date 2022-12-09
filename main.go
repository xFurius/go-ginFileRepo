package main

// check if the status codes are valid
// split code for clarity

import (
	"context"
	"errors"
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

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var usersCol *mongo.Collection
var filesCol *mongo.Collection

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func init() {
	godotenv.Load(".env")
}

// database connection
func connectDB() *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	return c
}

// sign up
func signUp(ctx *gin.Context) {
	var data User
	err := ctx.BindJSON(&data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)

	//TODO:
	//		email regex //frontend side
	//		email verification //go-mail

	cost, _ := strconv.Atoi(os.Getenv("COST"))
	hash, err := bcrypt.GenerateFromPassword([]byte(data.Password), cost)
	if err != nil {
		log.Fatal(err)
	}

	res := usersCol.FindOne(context.Background(), bson.M{"E-mail": data.Email})
	if res.Err() == nil {
		ctx.Status(http.StatusNoContent)
		return
	}

	_, err = usersCol.InsertOne(context.Background(), bson.M{"E-mail": data.Email, "Password": hash})
	if err != nil {
		fmt.Println(err)
	}
	ctx.Status(http.StatusOK)
}

// sign in
func signIn(ctx *gin.Context) {
	var data User
	err := ctx.BindJSON(&data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)

	var dbRes User
	res := usersCol.FindOne(context.Background(), bson.M{"E-mail": data.Email})
	if res.Err() != nil {
		ctx.Status(http.StatusNotFound)
		return
	}
	res.Decode(&dbRes)
	bsonRaw, _ := res.DecodeBytes()
	v := bsonRaw.Index(0)
	_id := strings.Split(v.String(), ":")[2]
	r := strings.NewReplacer(`"`, ``, `}`, ``)
	_id = r.Replace(_id)
	fmt.Println(_id)

	err = bcrypt.CompareHashAndPassword([]byte(dbRes.Password), []byte(data.Password))
	if err != nil {
		ctx.Status(http.StatusForbidden)
		fmt.Println("forbidden")
		return
	}
	fmt.Println("valid data")

	token, err := generateToken(_id, data.Email)
	if err != nil {
		ctx.Status(http.StatusForbidden)
		fmt.Println(err)
		return
	}

	session := sessions.Default(ctx)
	session.Set("token", token)
	err = session.Save()
	if err != nil {
		fmt.Println(err)
	}
}

// token generation
func generateToken(userID, userEmail string) (string, error) {
	claims := jwt.MapClaims{}
	claims["role"] = "user"
	claims["_id"] = userID
	claims["sub"] = userEmail

	fmt.Println(claims)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(os.Getenv("TOKEN_SECRET")))

}

// token validation
func validateToken(ctx *gin.Context) (error, jwt.MapClaims) {
	token := getToken(ctx)
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return errors.New("unexpected signing method"), nil
		}
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})
	if err != nil {
		return err, nil
	}
	return nil, claims
}

// retreving token from session
func getToken(ctx *gin.Context) string {
	session := sessions.Default(ctx)
	token := session.Get("token")
	if token != nil {
		return token.(string)
	}
	return ""
}

// jwt middleware
func JWTMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		err, _ := validateToken(ctx)
		if err != nil {
			ctx.Status(http.StatusUnauthorized)
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}

// sign out
func signOut(ctx *gin.Context) {
	if token := getToken(ctx); token == "" {
		ctx.Status(http.StatusUnauthorized)
		return
	}

	session := sessions.Default(ctx)
	session.Delete("token")
	err := session.Save()
	if err != nil {
		fmt.Println(err)
	}
	ctx.Status(http.StatusOK)
}

// upload
func upload(ctx *gin.Context) {
	file, err := ctx.FormFile("test")
	if err != nil {
		log.Fatal(err)
	}
	source := rand.NewSource(time.Now().Unix())
	r := source.Int63()
	fmt.Println(int(r))
	fileName := strings.ReplaceAll(file.Filename, " ", "_")
	filename := strconv.Itoa(int(r)) + fileName
	filesCol.InsertOne(context.Background(), bson.M{"E-mail": getEmail(ctx), "FileName": filename})
	err = ctx.SaveUploadedFile(file, "./files/"+filename)
	fmt.Println(err)
}

// get email form token
func getEmail(ctx *gin.Context) string {
	err, claims := validateToken(ctx)
	if err != nil {
		ctx.Status(http.StatusForbidden)
	}

	fmt.Println(claims)

	return claims["sub"].(string)
}

// displaying files uploaded by logged in user
func viewFiles(ctx *gin.Context) {
	user := getEmail(ctx)
	cursor, err := filesCol.Find(context.Background(), bson.D{{"E-mail", user}})
	if err != nil {
		fmt.Println(err)
		return
	}

	var res []bson.M
	if err = cursor.All(context.Background(), &res); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(res)

	fmt.Fprintln(ctx.Writer, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<link rel="stylesheet" href="styleView.css">
		<title>Document</title>
	</head>`)
	fmt.Fprintln(ctx.Writer, `<body><form id="form">`)
	for i, v := range res {
		toSend := `<input type="checkbox" value="` + v["FileName"].(string) + `" name="file" id="file` + strconv.Itoa(i) + `"><label for="file` + strconv.Itoa(i) + `">` + v["FileName"].(string) + `</label>`
		fmt.Fprintln(ctx.Writer, toSend)
	}
	fmt.Fprintln(ctx.Writer, `<input type="submit" formmethod="post" formaction="/user/downloadFile" value="download">
	<input type="submit" formmethod="post" formaction="/user/deleteFile" value="DELETE">
	</form></body></html>`)
}

// file download
// one file at a time for now
func download(ctx *gin.Context) {
	res, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		log.Fatal(err)
	}
	res = res[5:]
	fmt.Println(string(res))

	ctx.Header("Content-Disposition", "attachment; filename="+string(res))
	ctx.Header("Content-Type", ctx.GetHeader("Content-Type"))
	file, err := os.OpenFile("./files/"+string(res), os.O_RDONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	_, err = io.Copy(ctx.Writer, file)
	fmt.Println(err)

}

// file deletion
func delete(ctx *gin.Context) {
	fmt.Println("del")
	res, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		fmt.Println(err)
	}
	res = res[5:]
	fmt.Println(string(res))
	_, err = filesCol.DeleteOne(context.Background(), bson.D{{"FileName", string(res)}})
	fmt.Println(err)

	location := url.URL{Path: "/user/viewFiles"}
	ctx.Redirect(http.StatusFound, location.RequestURI())

	path := "./files/" + string(res)
	os.Remove(path)
}

func main() {
	client := connectDB()
	usersCol = client.Database("go-ginFileRepo").Collection("Users")
	filesCol = client.Database("go-ginFileRepo").Collection("Files")

	router := gin.Default()
	router.LoadHTMLGlob("./html/*")

	store := sessions.NewCookieStore([]byte(os.Getenv("TOKEN_SECRET")))
	router.Use(sessions.Sessions("session", store))

	router.GET("/signUp", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "signUp.html", nil)
	})
	router.POST("/signUp", signUp)

	router.GET("/signIn", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "signIn.html", nil)
	})
	router.POST("/signIn", signIn)
	router.GET("/signOut", signOut)

	user := router.Group("/user")
	user.Use(JWTMiddleware())
	user.GET("/viewFiles", viewFiles)
	user.POST("/downloadFile", download)
	user.GET("/uploadFile", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "upload.html", nil)
	})
	user.POST("/uploadFile", upload)
	user.StaticFile("/styleView.css", "./html/styleView.css")
	user.POST("/deleteFile", delete)

	router.Run()
}

//profile view
//acc deletion
//password change
//some status bar indicating upload state
//
