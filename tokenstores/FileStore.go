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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type fileTokenStore struct {
	logger *zap.Logger
	Path   string
}

func NewFileTokenStore(path string, logger *zap.Logger) *fileTokenStore {
	return &fileTokenStore{Path: path, logger: logger.Named("FileStore")}
}

func (f *fileTokenStore) Read(character string, scopes ...string) (*oauth2.Token, error) {
	dataPath := path.Join(f.Path)
	data, err := ioutil.ReadDir(dataPath)
	if err != nil {
		return nil, err
	}
	tokens := make([]*TokenItem, 0)
	for _, fd := range data {
		token := new(TokenItem)
		fData, err := ioutil.ReadFile(path.Join(dataPath, fd.Name()))
		if err != nil {
			continue
		}
		if err := json.Unmarshal(fData, &token); err != nil {
			continue
		}
		if token.CharacterName == character {
			tokens = append(tokens, token)
		}
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

func (f *fileTokenStore) Create(token *oauth2.Token) error {
	f.logger.Named("Create").Info("create", zap.String("name", GetName(token)), zap.String("jti", GetJTI(token)))
	dataPath := path.Join(f.Path)
	if err := os.MkdirAll(dataPath, 0700); err != nil {
		return err
	}
	tData, err := json.MarshalIndent(GetDecoded(token), "", " ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path.Join(dataPath, fmt.Sprintf("%s.json", GetJTI(token))), tData, 0660)
}

func (f *fileTokenStore) Update(oldtoken *oauth2.Token, newtoken *oauth2.Token) error {
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

func (f *fileTokenStore) Delete(token *oauth2.Token) error {
	f.logger.Named("Delete").Info("delete", zap.String("jti", GetJTI(token)))
	dataPath := path.Join(f.Path)
	return os.RemoveAll(path.Join(dataPath, fmt.Sprintf("%s.json", GetJTI(token))))
}
