/*
 *    Copyright 2021 FerociousBite and Contributors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package tokenstores

import (
	"context"
	"fmt"
	"net/url"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type mongoTokenStore struct {
	db         *mongo.Client
	logger     *zap.Logger
	Database   string
	collection string
}

func (m *mongoTokenStore) Create(token *oauth2.Token) error {
	m.logger.Named("Create").Debug("create", zap.String("name", GetName(token)), zap.String("jti", GetJTI(token)))
	collection := m.db.Database(m.Database).Collection(m.collection)
	item := GetDecoded(token)
	if _, err := collection.UpdateOne(context.Background(),
		bson.M{
			"OwnerHash":   bson.M{"$eq": item.OwnerHash},
			"characterID": bson.M{"$eq": item.CharacterID},
			"scopes":      bson.M{"$eq": item.Scopes},
		},
		bson.M{"$set": item}, options.Update().SetUpsert(true)); err != nil {
		return err
	}
	return nil
}

func (m *mongoTokenStore) Read(Character string, scopes ...string) (*oauth2.Token, error) {
	tokens := make([]*TokenItem, 0)
	collection := m.db.Database(m.Database).Collection(m.collection)
	r, err := collection.Find(context.Background(), bson.M{"CharacterName": Character})
	defer r.Close(context.Background())
	if err != nil {
		return nil, err
	}
	for r.Next(context.Background()) {
		item := new(TokenItem)
		if err := r.Decode(item); err != nil {
			return nil, err
		}
		tokens = append(tokens, item)
	}

	for i := range tokens {
		oat := &oauth2.Token{
			AccessToken:  tokens[i].AccessToken,
			TokenType:    tokens[i].TokenType,
			RefreshToken: tokens[i].RefreshToken,
			Expiry:       tokens[i].Expiry,
		}
		if MatchScopes(oat, scopes...) {
			m.logger.Named("Read").Info("match", zap.String("character", Character), zap.String("jti", GetJTI(oat)))
			return oat, nil
		}
	}
	for i := range tokens {
		oat := &oauth2.Token{
			AccessToken:  tokens[i].AccessToken,
			TokenType:    tokens[i].TokenType,
			RefreshToken: tokens[i].RefreshToken,
			Expiry:       tokens[i].Expiry,
		}
		if ContainsScopes(oat, scopes...) {
			m.logger.Named("Read").Info("pmatch", zap.String("character", Character), zap.String("jti", GetJTI(oat)))
			return oat, nil
		}
	}
	return nil, ErrTokenNotFound
}

func (m *mongoTokenStore) Update(oldtoken *oauth2.Token, newtoken *oauth2.Token) error {
	m.logger.Named("Update").Debug("update",
		zap.String("old", GetName(oldtoken)),
		zap.String("new", GetName(newtoken)),
		zap.String("jti-old", GetJTI(oldtoken)),
		zap.String("jti-new", GetJTI(newtoken)))
	return m.Create(newtoken)
	// err := m.Create(newtoken)
	// if err != nil {
	// 	return err
	// }
	// return m.Delete(oldtoken)
}

func (m *mongoTokenStore) Delete(token *oauth2.Token) error {
	m.logger.Named("Delete").Debug("delete", zap.String("jti", GetJTI(token)))
	collection := m.db.Database(m.Database).Collection(m.collection)
	if _, err := collection.DeleteOne(context.Background(), bson.M{"JTI": GetJTI(token)}); err != nil {
		return err
	}
	return nil
}

func NewMongoTokenStore(db *mongo.Client, database string, collection string, logger *zap.Logger) TokenStore {
	collectionSrv := db.Database(database).Collection(collection)
	_, _ = collectionSrv.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{"JTI", 1}, {"CharacterName", 1}, {"characterID", 1}},
	})
	_, _ = collectionSrv.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys:    bson.D{{"OwnerHash", 1}, {"CharacterName", 1}, {"characterID", 1}, {"scopes", 1}},
		Options: options.Index().SetUnique(true),
	})
	return &mongoTokenStore{db: db, Database: database, collection: collection, logger: logger.Named("MongoStore")}
}

func NewMongoClient(user, password, host, port string, usessl bool, logger *zap.Logger) *mongo.Client {
	mg, err := mongo.NewClient(options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s@%s:%s/?ssl=%t", url.QueryEscape(user), url.QueryEscape(password), host, port, usessl)))
	if err != nil {
		logger.Named("SETUP").Named("MONGO").Fatal("unable to create mongo client", zap.Error(err))
		return nil
	}
	if err = mg.Connect(context.Background()); err != nil {
		logger.Named("SETUP").Named("MONGO").Fatal("unable to connect", zap.Error(err))
		return nil
	}
	if err = mg.Ping(context.Background(), nil); err != nil {
		logger.Named("SETUP").Named("MONGO").Fatal("unable to ping", zap.Error(err))
		return nil
	}
	return mg
}
