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
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

type TokenItem struct {
	ID            [12]byte  `json:"_id,omitempty" bson:"_id,omitempty"`
	AccessToken   string    `bson:"AccessToken" json:"token"`
	RefreshToken  string    `bson:"RefreshToken" json:"refresh_token"`
	TokenType     string    `bson:"TokenType" json:"token_type"`
	CharacterName string    `bson:"CharacterName" json:"character_name"`
	CharacterID   int32     `bson:"characterID" json:"character_id"`
	Expiry        time.Time `bson:"Expiry" json:"expiry"`
	OwnerHash     string    `bson:"OwnerHash" json:"owner"`
	JTI           string    `bson:"JTI" json:"jti"`
	Scopes        []string  `bson:"scopes" json:"scopes"`
}

var ErrTokenNotFound = errors.New("token not found")
var ErrTokenInvalid = errors.New("token is invalid")

type TokenStore interface {
	Create(token *oauth2.Token) error
	Read(CharacterID string, Scopes ...string) (*oauth2.Token, error)
	Update(oldtoken *oauth2.Token, newtoken *oauth2.Token) error
	Delete(token *oauth2.Token) error
}

func scopeInList(scope string, list []string) bool {
	i := sort.SearchStrings(list, scope)
	return i < len(list) && list[i] == scope
}

func MatchScopes(token *oauth2.Token, scopes ...string) bool {
	scp := GetScopes(token)
	sort.Strings(scopes)
	if len(scp) != len(scopes) {
		return false
	}
	for i := range scp {
		if scp[i] != scopes[i] {
			return false
		}
	}
	return true
}

func ContainsScopes(token *oauth2.Token, scopes ...string) bool {
	scp := GetScopes(token)
	for _, s := range scopes {
		if !scopeInList(s, scp) {
			return false
		}
	}
	return true
}

func GetScopes(token *oauth2.Token) []string {
	t, _, err := new(jwt.Parser).ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return []string{}
	}
	scp := make([]string, 0)
	if mcs, ok := t.Claims.(jwt.MapClaims)["scp"].([]interface{}); ok {
		for _, sc := range mcs {
			scp = append(scp, sc.(string))
		}
	} else {
		scp = append(scp, t.Claims.(jwt.MapClaims)["scp"].(string))
	}
	sort.Strings(scp)
	return scp
}

func GetJTI(token *oauth2.Token) string {
	t, _, err := new(jwt.Parser).ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return ""
	}
	return t.Claims.(jwt.MapClaims)["jti"].(string)
}

func GetName(token *oauth2.Token) string {
	t, _, err := new(jwt.Parser).ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return ""
	}
	return t.Claims.(jwt.MapClaims)["name"].(string)
}

func GetID(token *oauth2.Token) int32 {
	t, _, err := new(jwt.Parser).ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return -1
	}
	sub := t.Claims.(jwt.MapClaims)["sub"].(string)
	parts := strings.Split(sub, ":")
	cid, err := strconv.ParseInt(parts[2], 10, 32)
	return int32(cid)
}

func GetDecoded(token *oauth2.Token) *TokenItem {
	item := new(TokenItem)
	t, _, err := new(jwt.Parser).ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return nil
	}
	cid, err := strconv.ParseInt(strings.Split(t.Claims.(jwt.MapClaims)["sub"].(string), ":")[2], 10, 32)
	if err != nil {
		return nil
	}
	uts := int64(t.Claims.(jwt.MapClaims)["exp"].(float64))
	item.AccessToken = token.AccessToken
	item.TokenType = token.TokenType
	item.RefreshToken = token.RefreshToken
	item.Expiry = time.Unix(uts, 0)
	item.OwnerHash = t.Claims.(jwt.MapClaims)["owner"].(string)
	item.Scopes = GetScopes(token)
	item.CharacterName = GetName(token)
	item.CharacterID = int32(cid)
	item.JTI = GetJTI(token)
	return item
}
