package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var secretKey = []byte("your-secret-key")

type User struct {
	Username string
	Password string
}

func getUserByUsername(username string) (*User, error) {
	// Здесь должен быть код для запроса пользователя из базы данных
	user := User{
		Username: "example",
		Password: "$2a$10$7j7YiKcWeG2lVak8zSQ1oujQ0/8YKLTVuLxSvOLxZoPTkZ/qE5G7K",
	}
	return &user, nil
}

func generateTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Здесь происходит чтение логина и пароля из запроса
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := getUserByUsername(username)
	if err != nil || user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid credentials")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid credentials")
		return
	}

	tokenString, err := generateToken(user.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error generating token")
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, tokenString)
}

func generateToken(username string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["authorized"] = true
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized access")
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Token is valid")
}

func main() {
	http.HandleFunc("/generate-token", generateTokenHandler)
	http.HandleFunc("/validate-token", validateTokenHandler)

	fmt.Println("Authorization Microservice started")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
