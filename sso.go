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

package eveauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"eveauth/tokenstores"
)

type SSO struct {
	mu          sync.RWMutex
	config      *oauth2.Config
	token       *oauth2.Token
	scopes      []string
	character   string
	characterID int32
	pkce        *pkce
	store       tokenstores.TokenStore
	logger      *zap.Logger
	validator   func(*jwt.Token) (interface{}, error)
}

func (c *SSO) GetCharacter() string {
	return c.character
}

func (c *SSO) CharacterID() int32 {
	return c.characterID
}

func (c *SSO) Scopes() []string {
	return c.scopes
}

func (c *SSO) AuthURL() string {
	c.pkce = makePKCE()
	return c.config.AuthCodeURL(
		c.pkce.state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challange", c.pkce.codeChallange),
		oauth2.SetAuthURLParam("code_challange_method", c.pkce.codeChallangeMethod),
	)
}

func (c *SSO) ValidState(state string) bool {
	if c.pkce != nil {
		return state == c.pkce.state
	}
	return false
}

func (c *SSO) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	if c.pkce == nil {
		return nil, errors.New("AuthRequest not created yet")
	}
	t, err := c.config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", c.pkce.codeVerifier),
	)
	c.pkce = nil
	return t, err
}

func (c *SSO) AuthInfoWriter() runtime.ClientAuthInfoWriter {
	return runtime.ClientAuthInfoWriterFunc(func(r runtime.ClientRequest, _ strfmt.Registry) error {
		if t, e := c.Token(); e != nil {
			return e
		} else {
			return r.SetHeaderParam("Authorization", "Bearer "+t.AccessToken)
		}
	})
}

func (c *SSO) Save(t *oauth2.Token) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = t
	c.logger.Named("Save").Debug("JWT", zap.Any("Key", t.AccessToken))
	return c.store.Create(t)
}

func (c *SSO) valid() error {
	if _, err := jwt.Parse(c.token.AccessToken, c.validator); err != nil {
		c.logger.Warn("token validation failed", zap.Error(err))
		return err
	}
	return nil
}

func (c *SSO) refresh(ctx context.Context) *oauth2.Token {
	ts := c.config.TokenSource(ctx, c.token)
	refreshed, err := ts.Token()
	if err != nil {
		return nil
	}
	return refreshed
}

func (c *SSO) Token() (*oauth2.Token, error) {
	// Token HAVE TO BE thread safe
	c.mu.Lock()
	defer c.mu.Unlock()

	var err error
	c.logger.Named("Token").Debug("getting token", zap.String("name", c.character), zap.Strings("scopes", c.scopes))
	// check if token is nil
	if c.token == nil {

		// read from token store
		c.token, err = c.store.Read(c.character, c.scopes...)

		if err != nil {
			// nothing in tokenstore ... unknown token
			return nil, errors.WithMessagef(err, "AuthURL: %s", c.AuthURL())
		}
	}
	// check if token is actually valid
	if err := c.valid(); err != nil {
		if err.(*jwt.ValidationError).Errors == jwt.ValidationErrorUnverifiable {
			return nil, err
		}
		// refresh the invalid token
		ctx, cancel := context.WithTimeout(context.TODO(), 20*time.Second)
		defer cancel()
		refreshed := c.refresh(ctx)
		if refreshed == nil {
			// if it was empty token we get here or if refresh failed because token is revoked - delete the stored token
			_ = c.store.Delete(c.token)
			return nil, errors.New("refresh token is nil, stored token deleted")
		}

		if refreshed.AccessToken != c.token.AccessToken || refreshed.RefreshToken != c.token.RefreshToken {
			// our access token or refresh token changed
			c.logger.Named("Token").Debug("refreshed token.", zap.String("token", tokenstores.GetJTI(c.token)), zap.String("newToken", tokenstores.GetJTI(refreshed)))
			// update token in store
			if err := c.store.Update(c.token, refreshed); err != nil {
				c.logger.Named("Token").Error("unable to save local token", zap.Error(err))
				return nil, err
			}
			// update token in struct
			c.token = refreshed
		}
	}
	// here we 100% have valid token , get the character ID
	c.characterID = tokenstores.GetID(c.token)
	c.logger.Named("Token").Debug("found token", zap.String("name", c.character), zap.String("token", tokenstores.GetJTI(c.token)), zap.Strings("scopes", c.scopes))
	return c.token, nil
}

func (c *SSO) HaveScopes(scopes ...string) bool {
	token, err := c.Token()
	if err != nil {
		return false
	}
	return tokenstores.ContainsScopes(token, scopes...)
}

func (c *SSO) MatchScopes(scopes ...string) bool {
	token, err := c.Token()
	if err != nil {
		return false
	}
	return tokenstores.MatchScopes(token, scopes...)
}

func NewSSO(store tokenstores.TokenStore, Character string, config *oauth2.Config, logger *zap.Logger, validator func(*jwt.Token) (interface{}, error)) *SSO {
	return &SSO{
		config:    config,
		token:     nil,
		character: Character,
		scopes:    config.Scopes,
		store:     store,
		logger:    logger.Named("SSOClient"),
		validator: validator,
	}
}

type pkce struct {
	state               string
	codeVerifier        string
	codeChallange       string
	codeChallangeMethod string
}

func makePKCE() *pkce {
	sha := sha256.New()
	verifier := make([]byte, 32)
	if n, err := rand.Read(verifier); err != nil || n != 32 {
		return nil
	}
	encodedVerifier := base64.RawURLEncoding.EncodeToString(verifier)
	shaEncodedVerifier := sha.Sum([]byte(encodedVerifier))
	challange := base64.RawURLEncoding.EncodeToString(shaEncodedVerifier)
	return &pkce{
		state:               uuid.New().String(),
		codeVerifier:        encodedVerifier,
		codeChallange:       challange,
		codeChallangeMethod: "S256",
	}
}
