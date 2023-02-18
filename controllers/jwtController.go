package controllers

import (
	"context"
	"errors"
	"fmt"
	"go-ginFileRepo/models"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

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

// sign up
func SignUp(ctx *gin.Context) {
	var data models.User
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

	res := UsersCol.FindOne(context.Background(), bson.M{"E-mail": data.Email})
	if res.Err() == nil {
		ctx.Status(http.StatusNoContent)
		return
	}

	_, err = UsersCol.InsertOne(context.Background(), bson.M{"E-mail": data.Email, "Password": hash})
	if err != nil {
		fmt.Println(err)
	}
	ctx.Status(http.StatusOK)
}

// sign in
func SignIn(ctx *gin.Context) {
	var data models.User
	err := ctx.BindJSON(&data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)

	var dbRes models.User
	res := UsersCol.FindOne(context.Background(), bson.M{"E-mail": data.Email})
	if res.Err() != nil {
		ctx.Status(http.StatusNotFound)
		return
	}
	fmt.Println("res: ", res)
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

// sign out
func SignOut(ctx *gin.Context) {
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
func GetEmailFromToken(ctx *gin.Context) string {
	err, claims := validateToken(ctx)
	if err != nil {
		ctx.Status(http.StatusForbidden)
	}

	fmt.Println(claims)

	return claims["sub"].(string)
}
