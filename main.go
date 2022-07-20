package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type response struct {
	Ok    bool
	Error string
	Token string
}

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

func homepage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	res := map[string]bool{
		"ok": true,
	}
	jsonResp, _ := json.Marshal(res)
	w.Write(jsonResp)
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
	w.Header().Set("Content-Type", "application/json")
	r.ParseForm()
	user := User{}
	for key, value := range r.Form {
		if value[0] == "" {
			res := map[string]string{
				"ok":    `false`,
				"error": "no username or password provided",
			}
			w.WriteHeader(400)
			jsonResp, _ := json.Marshal(res)
			w.Write(jsonResp)
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
			w.WriteHeader(400)
			res := map[string]string{
				"ok":    `false`,
				"error": "user already exists",
			}
			jsonResp, _ := json.Marshal(res)
			w.Write(jsonResp)
			return
		}
	}

	tokenn := GenerateToken(user.username)

	user.Token = tokenn
	AllUsers = append(AllUsers, user)
	if tokenn != "" {
		w.WriteHeader(201)
		res := map[string]string{
			"ok":    `true`,
			"token": tokenn,
		}
		jsonResp, _ := json.Marshal(res)
		w.Write(jsonResp)
		return
	}
}

func logIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	r.ParseForm()
	user := [2]string{}
	for key, value := range r.Form {
		if value[0] == "" {
			w.WriteHeader(400)
			res := map[string]string{
				"ok":    `false`,
				"error": "no username or password provided",
			}
			jsonResp, _ := json.Marshal(res)
			w.Write(jsonResp)
			// fmt.Fprintf(w, `{"ok":false,"error":"no username or password provided"}`)
			return
		}
		switch key {
		case "password":
			user[0] = value[0]
		case "username":
			user[1] = value[0]
		}
	}
	if len(AllUsers) == 0 {
		w.WriteHeader(400)
		res := map[string]string{
			"ok":    `false`,
			"error": "invalid username or password",
		}
		jsonResp, _ := json.Marshal(res)
		w.Write(jsonResp)
		// fmt.Fprintf(w, `{"ok":false,"error":"invalid username or password"}`)
		return
	}
	// token := GenerateToken(user[1])
	token := ""
	for i, v := range AllUsers {
		if v.username == user[1] {
			if err := bcrypt.CompareHashAndPassword([]byte(v.password), []byte(user[0])); err != nil {
				w.WriteHeader(400)
				res := map[string]string{
					"ok":    `false`,
					"error": "invalid username or password",
				}
				jsonResp, _ := json.Marshal(res)
				w.Write(jsonResp)
				return
			} else {
				// v.Token = token
				token = v.Token
				break
			}
		} else if i == len(AllUsers)-1 {
			w.WriteHeader(400)
			res := map[string]string{
				"ok":    `false`,
				"error": "invalid username or password",
			}
			jsonResp, _ := json.Marshal(res)
			w.Write(jsonResp)
			return
		}
	}
	w.WriteHeader(200)
	res := map[string]string{
		"ok":    `true`,
		"token": token,
	}
	jsonResp, _ := json.Marshal(res)
	w.Write(jsonResp)
	// fmt.Fprintf(w, `{"ok":true,"token":"%v"}`, token) //////
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
	w.Header().Set("Content-Type", "application/json")
	r.ParseForm()
	token := r.Form["Authorization"][0]
	text := r.Form["text"][0]
	f, user := isAthourised(token)
	if !f {
		w.WriteHeader(401)
		return
	}
	if text == "" {
		w.WriteHeader(400)
		res := map[string]string{
			"ok":    `false`,
			"error": "no text provided",
		}
		jsonResp, _ := json.Marshal(res)
		w.Write(jsonResp)
		// w.WriteHeader(400)
		// fmt.Fprintf(w, `{"ok":false,"error":"no text provided"}`)
		return
	}
	t := tiket{
		text: text,
		user: user,
	}
	// fmt.Println(t)
	Alltikets = append(Alltikets, t)
	w.WriteHeader(201)
	res := map[string]bool{
		"ok": true,
	}
	jsonResp, _ := json.Marshal(res)
	w.Write(jsonResp)
	return
}

func AllSuggestions(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	res := []map[string]string{}
	w.WriteHeader(200)
	for _, v := range Alltikets {
		tmp := map[string]string{
			"text": v.text,
			"user": v.user,
		}
		res = append(res, tmp)
	}
	jsonResp, _ := json.Marshal(res)
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
	// http.Handle("/", r)
	srv := &http.Server{
		Handler: r,
		Addr:    ":80",
	}

	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalln("Cannot server the server:", err)
	}

}
