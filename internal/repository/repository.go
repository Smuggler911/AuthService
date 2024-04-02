package repository

import (
	jwt2 "AuthService/internal/lib/jwt"
	"AuthService/internal/repository/models"
	"AuthService/pkg/client/mongoDb"
	"context"
	"encoding/base64"
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type Response struct {
	AccessToken string `json:"access_token"`
}

func LoginUser(w http.ResponseWriter, r *http.Request) {

	client := mongoDb.NewClient()
	coll := client.Database("users").Collection("user")

	var _, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var userbody models.User
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&userbody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	err = coll.FindOne(context.TODO(), bson.M{
		"username": userbody.Username,
	}).Decode(&user)

	defer cancel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userbody.Password))
	defer cancel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessToken, refreshToken, err := jwt2.GenerateTokenPair(user)

	data := base64.StdEncoding.EncodeToString([]byte(refreshToken))
	Rcookie := http.Cookie{
		Name:     "refresh_token",
		Value:    data,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &Rcookie)
	Acookie := http.Cookie{
		Name:     "Authorization",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &Acookie)
	w.Header().Set("Content-Type", "application/json")

	responseLogin := Response{
		AccessToken: accessToken,
	}
	json.NewEncoder(w).Encode(&responseLogin)

}
func UpdateToken(w http.ResponseWriter, r *http.Request) {

	user, ok := r.Context().Value("user").(models.User)
	if !ok {
		http.Error(w, "user not found", http.StatusInternalServerError)
	}

	accessToken, rToken, err := jwt2.GenerateTokenPair(user)

	if err != nil {
		http.Error(w, "failed to generate token pair ", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	Acookie := http.Cookie{
		Name:     "Authorization",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	refreshTokenData := base64.StdEncoding.EncodeToString([]byte(rToken))
	Rcookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenData,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	resp := Response{
		AccessToken: accessToken,
	}
	http.SetCookie(w, &Rcookie)
	http.SetCookie(w, &Acookie)
	json.NewEncoder(w).Encode(resp)

}
