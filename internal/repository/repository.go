package repository

import (
	jwt2 "AuthService/internal/lib/jwt"
	"AuthService/internal/repository/models"
	"AuthService/pkg/client/mongoDb"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type Response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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
	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    data,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+accessToken)

	responseLogin := Response{
		AccessToken:  accessToken,
		RefreshToken: data,
	}
	json.NewEncoder(w).Encode(&responseLogin)

}
func UpdateToken(w http.ResponseWriter, r *http.Request) {

	rCookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "refresh token not found", http.StatusUnauthorized)
		return
	}

	refreshToken := rCookie.Value

	decodedRefreshToken, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		http.Error(w, "invalid refresh token ", http.StatusUnauthorized)
		return
	}

	claims := jwt.MapClaims{}
	rtString := string(decodedRefreshToken)

	_, err = jwt.ParseWithClaims(rtString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwt2.Secret), nil
	})

	Id := claims["sub"].(string)

	client := mongoDb.NewClient()
	coll := client.Database("users").Collection("user")
	var user models.User

	objectId, err := primitive.ObjectIDFromHex(Id)
	filter := bson.M{"_id": objectId}

	coll.FindOne(context.TODO(), filter).Decode(&user)

	accessToken, rToken, err := jwt2.GenerateTokenPair(user)
	if err != nil {
		http.Error(w, "failed to generate token pair ", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+accessToken)

	refreshTokenData := base64.StdEncoding.EncodeToString([]byte(rToken))
	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenData,
		Path:     "/",
		HttpOnly: true,
	}

	resp := Response{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenData,
	}
	http.SetCookie(w, &cookie)

	json.NewEncoder(w).Encode(resp)

}
