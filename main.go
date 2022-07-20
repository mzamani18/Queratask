package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/iancoleman/orderedmap"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	username string
	password string
	Token    string
}

type tiket struct {
	user string
	text string
}

var AllUsers []User
var Alltikets []tiket

func ResponseBuilder(token, errorMsg string, isOk bool, statusCode int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	res := orderedmap.New()
	res.Set("ok", isOk)
	if errorMsg != "" {
		res.Set("error", errorMsg)
	}
	if token != "" {
		res.Set("token", token)
	}
	w.WriteHeader(statusCode)
	jsonResp, _ := json.Marshal(res)
	w.Write(jsonResp)
}

func homepage(w http.ResponseWriter, _ *http.Request) {
	ResponseBuilder("", "", true, 200, w)
	return
}

func GenerateToken(username string) string {
	var mySigningKey = []byte("mohammad")
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		return ""
	}
	return tokenString
}

func signUp(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	user := User{}
	for key, value := range r.Form {
		if value[0] == "" {
			ResponseBuilder("", "no username or password provided", false, 400, w)
			return
		}
		switch key {
		case "password":
			pass, _ := bcrypt.GenerateFromPassword([]byte(value[0]), 12)
			user.password = string(pass)
		case "username":
			user.username = value[0]
		}
	}
	for _, v := range AllUsers {
		if v.username == user.username {
			ResponseBuilder("", "user already exists", false, 400, w)
			return
		}
	}

	newToken := GenerateToken(user.username)
	user.Token = newToken

	AllUsers = append(AllUsers, user)
	if newToken != "" {
		ResponseBuilder(newToken, "", true, 201, w)
		return
	}
}

func logIn(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	user := User{}
	user.username = r.Form["username"][0]
	user.password = r.Form["password"][0]

	if user.username == "" || user.password == "" {
		ResponseBuilder("", "no username or password provided", false, 400, w)
		return
	}
	if len(AllUsers) == 0 {
		ResponseBuilder("", "invalid username or password", false, 400, w)
		return
	}
	token := GenerateToken(user.username)
	// token := ""
	for i, v := range AllUsers {
		if v.username == user.username {
			if err := bcrypt.CompareHashAndPassword([]byte(v.password), []byte(user.password)); err != nil {
				ResponseBuilder("", "invalid username or password", false, 400, w)
				return
			} else {
				v.Token = token
				break
			}
		} else if i == len(AllUsers)-1 {
			ResponseBuilder("", "invalid username or password", false, 400, w)
			return
		}
	}
	ResponseBuilder(token, "", true, 200, w)
	return
}

func isAthourised(tokenn string) (bool, string) {
	var mySigningKey = []byte("mohammad")
	token, _ := jwt.Parse(tokenn, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error in parsing")
		}
		return mySigningKey, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true, fmt.Sprint(claims["username"])
	}
	return false, ""
}

func Suggestions(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	token := r.Header.Get("Authorization")
	text := r.Form["text"][0]
	isAthourised, user := isAthourised(token)
	if !isAthourised {
		w.WriteHeader(401)
		return
	}
	if text == "" {
		ResponseBuilder("", "no text provided", false, 400, w)
		return
	}
	t := tiket{
		text: text,
		user: user,
	}
	Alltikets = append(Alltikets, t)
	ResponseBuilder("", "", true, 201, w)
	return
}

func AllSuggestions(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	allOrderedTikets := []*orderedmap.OrderedMap{}
	for _, v := range Alltikets {
		o := orderedmap.New()
		o.Set("user", v.user)
		o.Set("text", v.text)
		allOrderedTikets = append(allOrderedTikets, o)
	}
	w.WriteHeader(200)
	jsonResp, _ := json.Marshal(allOrderedTikets)
	w.Write(jsonResp)
	return
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", homepage).Methods("GET")
	r.HandleFunc("/signup", signUp).Methods("POST")
	r.HandleFunc("/login", logIn).Methods("POST")
	r.HandleFunc("/suggestions", Suggestions).Methods("POST")
	r.HandleFunc("/suggestions", AllSuggestions).Methods("GET")

	srv := &http.Server{
		Handler: r,
		Addr:    ":80",
	}

	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalln("Cannot server the server:", err)
	}
}
