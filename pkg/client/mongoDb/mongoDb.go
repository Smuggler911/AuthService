package mongoDb

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
)

func NewClient() *mongo.Client {
	mongoDBURI := os.Getenv("MONGO_URI")

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(mongoDBURI).SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		return nil
	}

	if err = client.Database("users").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Err(); err != nil {
		return nil
	}

	return client
}
