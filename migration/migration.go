package main

import (
	"AuthService/config"
	"AuthService/internal/repository/models"
	"AuthService/pkg/client/mongoDb"
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	config.LoadConfig()
}

func main() {
	client := mongoDb.NewClient()

	coll := client.Database("users").Collection("user")

	password := "5678"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		fmt.Printf("Error generating hash for password: %v\n", err)
		return
	}

	doc := models.User{
		Username: "user",
		Password: string(hash),
	}

	result, err := coll.InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("Error inserting doc: %v\n", err)
	}

	fmt.Printf("Inserted document with _id: %v\n", result.InsertedID)

}
