package main

// check if the status codes are valid
// split code for clarity

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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

var db *mongo.Collection

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

	res := db.FindOne(context.Background(), bson.M{"E-mail": data.Email})
	if res.Err() == nil {
		ctx.Status(http.StatusNoContent)
		return
	}

	_, err = db.InsertOne(context.Background(), bson.M{"E-mail": data.Email, "Password": hash})
	if err != nil {
		fmt.Println(err)
	}
	ctx.Status(http.StatusOK)
}

func signIn(ctx *gin.Context) {
	var data User
	err := ctx.BindJSON(&data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)

	var dbRes User
	res := db.FindOne(context.Background(), bson.M{"E-mail": data.Email})
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

	token, err := generateToken(_id, dbRes.Email)
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

func generateToken(userID, userEmail string) (string, error) {
	claims := jwt.MapClaims{}
	claims["role"] = "user"
	claims["_id"] = userID
	claims["sub"] = userEmail

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(os.Getenv("TOKEN_SECRET")))

}

func validateToken(ctx *gin.Context) error {
	token := getToken(ctx)
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})
	if err != nil {
		return err
	}
	return nil
}

func getToken(ctx *gin.Context) string {
	session := sessions.Default(ctx)
	token := session.Get("token")
	if token != nil {
		return token.(string)
	}
	return ""
}

func JWTMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		fmt.Println(ctx.Request.Cookie("token"))
		err := validateToken(ctx)
		if err != nil {
			ctx.Status(http.StatusUnauthorized)
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}

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

func upload(ctx *gin.Context) {
	file, err := ctx.FormFile("test")
	if err != nil {
		log.Fatal(err)
	}
	err = ctx.SaveUploadedFile(file, "./files/"+file.Filename) //change path
	fmt.Println(err)
}

func main() {
	client := connectDB()
	db = client.Database("go-ginFileRepo").Collection("Users")

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

	user := router.Group("/files")
	user.Use(JWTMiddleware())
	user.GET("/viewFiles", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, bson.M{"status": 200})
	})
	user.GET("/upload", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "upload.html", nil)
	})

	user.POST("/upload", upload)

	router.GET("/signOut", signOut)

	router.Run()
}
