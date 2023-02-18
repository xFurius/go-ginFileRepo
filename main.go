package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"

	controllers "go-ginFileRepo/controllers"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var Templates *template.Template

func init() {
	godotenv.Load(".env")
}

func main() {
	controllers.ConnectDB()

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
	router.POST("/signUp", controllers.SignUp)

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
	router.POST("/signIn", controllers.SignIn)
	router.GET("/signOut", controllers.SignOut)

	router.StaticFile("/html/style.css", "./html/style.css")
	router.StaticFile("/assets/stackedFiles.png", "./assets/stackedFiles.png")
	router.StaticFile("/assets/mail.png", "./assets/mail.png")
	router.StaticFile("/assets/padlock.png", "./assets/padlock.png")
	router.StaticFile("/assets/download.png", "./assets/download.png")
	router.StaticFile("/assets/delete.png", "./assets/delete.png")
	router.StaticFile("/assets/info.png", "./assets/info.png")
	router.StaticFile("/assets/upload.png", "./assets/upload.png")
	router.StaticFile("/assets/file.png", "./assets/file.png")
	router.StaticFile("/assets/user.png", "./assets/user.png")
	router.StaticFile("/assets/textFile.png", "./assets/textFile.png")
	router.StaticFile("/assets/imgFile.png", "./assets/imgFile.png")
	router.StaticFile("/assets/exeFile.png", "./assets/exeFile.png")
	router.StaticFile("/assets/videoFile.png", "./assets/videoFile.png")
	router.StaticFile("/assets/compressedFile.png", "./assets/compressedFile.png")
	router.StaticFile("/assets/audioFile.png", "./assets/audioFile.png")
	router.StaticFile("/assets/spreadsheetFile.png", "./assets/spreadsheetFile.png")

	user := router.Group("/user")
	user.Use(controllers.JWTMiddleware())
	user.GET("/viewFiles", func(ctx *gin.Context) {
		files, fileData := controllers.ViewUserFileData(ctx)
		fmt.Println(files)
		fmt.Println(fileData)
		data := struct {
			Email    string
			Files    []string
			FileData map[string][]string
		}{
			controllers.GetEmailFromToken(ctx), files, fileData,
		}
		if err := templates.ExecuteTemplate(ctx.Writer, "viewFiles.html", data); err != nil {
			fmt.Println(err)
		}
	})
	user.POST("/downloadFile", controllers.Download)
	user.GET("/uploadFile", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "upload.html", nil)
	})
	user.POST("/uploadFile", controllers.Upload)
	user.StaticFile("/styleView.css", "./html/styleView.css")
	user.POST("/deleteFile", controllers.Delete)
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
