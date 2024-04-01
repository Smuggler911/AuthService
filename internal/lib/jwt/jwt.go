package jwt

import (
	"AuthService/internal/repository/models"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var Secret string = "eertegftbhrdsger"

func GenerateTokenPair(user models.User) (at string, rt string, err error) {
	aToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Id,
		"exp": time.Now().Add(time.Minute * 30).Unix(),
	})

	accessToken, err := aToken.SignedString([]byte(Secret))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %v", err)
	}

	rToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Id,
		"exp": time.Now().Add(time.Hour * 24 * 30),
	})

	refreshToken, err := rToken.SignedString([]byte(Secret))
	return accessToken, refreshToken, nil
}
