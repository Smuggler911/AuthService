package middleware

import (
	"AuthService/internal/repository/models"
	"AuthService/pkg/client/mongoDb"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"os"
)

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aCookie, err := r.Cookie("Authorization")
		if err != nil {
			http.Error(w, "access token not found", http.StatusUnauthorized)
		}
		Secret := os.Getenv("SECRET_KEY")
		accessToken := aCookie.Value

		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(Secret), nil
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("error parsing token: %v", err), http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {

			var user models.User
			Id := claims["sub"].(string)

			client := mongoDb.NewClient()
			coll := client.Database("users").Collection("user")

			objectId, _ := primitive.ObjectIDFromHex(Id)
			filter := bson.M{"_id": objectId}

			coll.FindOne(context.TODO(), filter).Decode(&user)

			ctx := r.Context()

			ctx = context.WithValue(ctx, "user", user)

			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)

		}
	})
}

func RequireRefresh(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rCookie, err := r.Cookie("refresh_token")
		if err != nil {
			http.Error(w, "refresh token not found", http.StatusUnauthorized)
		}
		refreshToken := rCookie.Value

		decodedRefreshToken, err := base64.StdEncoding.DecodeString(refreshToken)
		if err != nil {
			http.Error(w, "invalid refresh token ", http.StatusUnauthorized)
		}
		rtString := string(decodedRefreshToken)

		Secret := os.Getenv("SECRET_KEY")

		claims := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(rtString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(Secret), nil
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("error parsing token: %v", err), http.StatusUnauthorized)
			return
		}
		Id := claims["sub"].(string)

		client := mongoDb.NewClient()
		coll := client.Database("users").Collection("user")

		var user models.User
		objectId, _ := primitive.ObjectIDFromHex(Id)
		filter := bson.M{"_id": objectId}

		coll.FindOne(context.TODO(), filter).Decode(&user)

		accessTokenUser, ok := r.Context().Value("user").(models.User)

		if !ok {
			http.Error(w, "user not found", http.StatusInternalServerError)
		}

		if user.Id == accessTokenUser.Id {
			ctx := r.Context()

			ctx = context.WithValue(ctx, "user", user)

			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)

		}
	})

}
