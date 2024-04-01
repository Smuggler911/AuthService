package main

import (
	"AuthService/config"
	"AuthService/internal/api"
	"AuthService/internal/server"
	"log"
	"os"
)

func init() {
	config.LoadConfig()

}
func main() {
	port := os.Getenv("PORT")

	handlers := new(api.Handler)
	srv := new(server.Server)

	if err := srv.Run(port, handlers.HandleRequests()); err != nil {
		log.Fatalln("Error starting server : ", err.Error())
	}

}
