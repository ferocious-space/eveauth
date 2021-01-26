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
	"github.com/ferocious-space/badgerhold"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type badgerTokenStore struct {
	logger *zap.Logger
	db     *badgerhold.Store
}

func NewBadgerTokenStore(logger *zap.Logger, db *badgerhold.Store) TokenStore {
	return &badgerTokenStore{db: db, logger: logger.Named("BadgerStore")}
}

func (f *badgerTokenStore) Read(character string, scopes ...string) (*oauth2.Token, error) {
	tokens := make([]TokenItem, 0)
	err := f.db.Find(&tokens, badgerhold.Where("CharacterName").Eq(character))
	if err != nil {
		return nil, err
	}
	for i := range tokens {
		oat := &oauth2.Token{
			AccessToken:  tokens[i].AccessToken,
			TokenType:    tokens[i].TokenType,
			RefreshToken: tokens[i].RefreshToken,
			Expiry:       tokens[i].Expiry,
		}
		if MatchScopes(oat, scopes...) {
			f.logger.Named("Read").Info("match", zap.String("character", character), zap.String("jti", GetJTI(oat)))
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
			f.logger.Named("Read").Info("pmatch", zap.String("character", character), zap.String("jti", GetJTI(oat)))
			return oat, nil
		}
	}
	return nil, ErrTokenNotFound
}

func (f *badgerTokenStore) Create(token *oauth2.Token) error {
	item := GetDecoded(token)
	f.logger.Named("Create").Info("create", zap.String("name", item.CharacterName), zap.String("jti", item.JTI))
	err := f.db.Insert(badgerhold.NextSequence(), item)
	if err != nil {
		return err
	}
	return f.db.Badger().Sync()
}

func (f *badgerTokenStore) Update(oldtoken *oauth2.Token, newtoken *oauth2.Token) error {
	f.logger.Named("Update").Info("update",
		zap.String("old", GetName(oldtoken)),
		zap.String("new", GetName(newtoken)),
		zap.String("jti-old", GetJTI(oldtoken)),
		zap.String("jti-new", GetJTI(newtoken)))
	// logrus.WithField("character", f.GetName(oldtoken)).WithField("JTI", f.GetJTI(oldtoken)).Infof("Replace with %s", f.GetJTI(newtoken))
	err := f.Create(newtoken)
	if err != nil {
		return err
	}
	return f.Delete(oldtoken)
}

func (f *badgerTokenStore) Delete(token *oauth2.Token) error {
	f.logger.Named("Delete").Info("delete", zap.String("jti", GetJTI(token)))
	item := GetDecoded(token)
	return f.db.DeleteMatching(item, badgerhold.Where("JTI").Eq(item.JTI))
}
