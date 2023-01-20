package main

// check if the status codes are valid
// split code for clarity

import (
	"context"
	"errors"
	"fmt"
	"html/template"
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
var templates *template.Template

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

// get email form token
func getEmail(ctx *gin.Context) string {
	err, claims := validateToken(ctx)
	if err != nil {
		ctx.Status(http.StatusForbidden)
	}

	fmt.Println(claims)

	return claims["sub"].(string)
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

	ext := strings.Split(file.Filename, ".")[len(strings.Split(file.Filename, "."))-1]
	fmt.Println(ext)

	replacer := strings.NewReplacer(" ", "_", "(", "_", ")", "_", ".", "_")
	fileName := replacer.Replace(file.Filename)
	filename := fileName + strconv.Itoa(int(r)) + "." + ext

	uploadDate := time.Now().Format("2006-01-02 3:04:05 pm")
	fmt.Println(uploadDate)

	filesCol.InsertOne(context.Background(), bson.M{"E-mail": getEmail(ctx), "FileName": filename, "UploadDate": uploadDate, "FileSize": file.Size, "FileType": strings.Split(filename, ".")[1]})
	err = ctx.SaveUploadedFile(file, "./files/"+filename)
	fmt.Println(err)
}

// displaying files uploaded by logged in user
func viewFilesData(ctx *gin.Context) ([]string, map[string][]string) {
	user := getEmail(ctx)
	cursor, err := filesCol.Find(context.Background(), bson.D{{"E-mail", user}})
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
			//uploadDate, fileSize, FileType
			// TODO: convert btyes to kb/mb/gb
			v["UploadDate"].(string), fmt.Sprint(v["FileSize"].(int64)), v["FileType"].(string),
		}
		fileData[v["FileName"].(string)] = temp
	}

	return files, fileData
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

	ctx.FileAttachment("./files/"+string(res), string(res))
}

// file deletion
func delete(ctx *gin.Context) {
	res, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(res))

	tempR := strings.ReplaceAll(string(res), "file=", "")
	files := strings.Split(tempR, "&")
	fmt.Println(files)

	for _, v := range files {
		_, err = filesCol.DeleteOne(context.Background(), bson.D{{"FileName", v}})
		path := "./files/" + v
		os.Remove(path)
	}

	location := url.URL{Path: "/user/viewFiles"}
	ctx.Redirect(http.StatusFound, location.RequestURI())

}

func main() {
	client := connectDB()
	usersCol = client.Database("go-ginFileRepo").Collection("Users")
	filesCol = client.Database("go-ginFileRepo").Collection("Files")

	templates, err := template.ParseGlob("./html/*.html")
	if err != nil {
		fmt.Println(err)
	}
	router := gin.Default()

	router.LoadHTMLGlob("./html/*.html")

	store := sessions.NewCookieStore([]byte(os.Getenv("TOKEN_SECRET")))
	router.Use(sessions.Sessions("session", store))

	router.GET("/signUp", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "signUp.html", nil)
	})
	router.POST("/signUp", signUp)

	router.GET("/signIn", func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		tkn := session.Get("token")
		fmt.Println(tkn)
		if tkn != "" && tkn != nil {
			location := url.URL{Path: "/user/viewFiles"}
			ctx.Redirect(http.StatusFound, location.RequestURI())
		}

		ctx.HTML(http.StatusOK, "signIn.html", nil)
	})
	router.POST("/signIn", signIn)
	router.GET("/signOut", signOut)

	router.StaticFile("/html/style.css", "./html/style.css")
	router.StaticFile("/assets/stacked-files.png", "./assets/stacked-files.png")
	router.StaticFile("/assets/mail.png", "./assets/mail.png")
	router.StaticFile("/assets/padlock.png", "./assets/padlock.png")
	router.StaticFile("/assets/download.png", "./assets/download.png")
	router.StaticFile("/assets/delete.png", "./assets/delete.png")
	router.StaticFile("/assets/info.png", "./assets/info.png")
	router.StaticFile("/assets/upload.png", "./assets/upload.png")
	router.StaticFile("/assets/files.png", "./assets/files.png")
	router.StaticFile("/assets/user.png", "./assets/user.png")

	user := router.Group("/user")
	user.Use(JWTMiddleware())
	user.GET("/viewFiles", func(ctx *gin.Context) {
		files, fileData := viewFilesData(ctx)
		fmt.Println(files)
		fmt.Println(fileData)
		data := struct {
			Email    string
			Files    []string
			FileData map[string][]string
		}{
			getEmail(ctx), files, fileData,
		}
		if err := templates.ExecuteTemplate(ctx.Writer, "viewFiles.html", data); err != nil {
			fmt.Println(err)
		}
	})
	user.POST("/downloadFile", download)
	user.GET("/uploadFile", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "upload.html", nil)
	})
	user.POST("/uploadFile", upload)
	user.StaticFile("/styleView.css", "./html/styleView.css")
	user.POST("/deleteFile", delete)
	// user.GET("/profile", func(ctx *gin.Context) {
	// 	if err := templates.ExecuteTemplate(ctx.Writer, "profile.html", map[string]interface{}{"twest": "test"}); err != nil {
	// 		fmt.Println(err)
	// 	}
	// })

	router.Run()
}

// profile view
// acc deletion
// password change
// some status bar indicating upload state
// download few files at once
// upload few files at once
