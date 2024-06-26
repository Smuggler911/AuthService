package jwt

import (
	"AuthService/internal/repository/models"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

func GenerateTokenPair(user models.User) (at string, rt string, err error) {
	Secret := os.Getenv("SECRET_KEY")

	aToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Id,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})

	accessToken, err := aToken.SignedString([]byte(Secret))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %v", err)
	}

	rToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Id,
		"exp": time.Now().Add(24 * 30 * 24 * time.Hour).Unix(),
	})

	refreshToken, err := rToken.SignedString([]byte(Secret))
	return accessToken, refreshToken, nil
}
