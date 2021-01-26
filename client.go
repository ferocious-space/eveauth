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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	goruntime "runtime"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/ferocious-space/durableclient"
	"github.com/ferocious-space/httpcache"
	"github.com/go-openapi/runtime"
	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	"github.com/lestrrat/go-jwx/jwk"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/oauth2"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/ferocious-space/eveapi/esi"

	"eveauth/tokenstores"
)

type Config struct {
	Key      string
	Secret   string
	Callback string
}

func (c Config) Load(path string, logger *zap.Logger) Config {
	cfg, err := os.Open(path)
	if err != nil {
		logger.Panic("config.json", zap.Error(err))
	}
	if err = jsoniter.NewDecoder(cfg).Decode(&c); err != nil {
		logger.Panic("config.json", zap.Error(err))
	}
	return c
}

type APIClient struct {
	metadata         *OAuthMetadata
	logger           *zap.Logger
	configHTTPClient *http.Client
	esiHTTPClient    *http.Client
	metaHTTPClient   *http.Client
	validator        func(*jwt.Token) (interface{}, error)
	jwkKeys          *jwk.Set
}

type OAuthMetadata struct {
	Issuer                                     string   `json:"issuer,omitempty"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                              string   `json:"token_endpoint,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported,omitempty"`
	JwksURI                                    string   `json:"jwks_uri,omitempty"`
	RevocationEndpoint                         string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
}

var MetadataURL = "https://login.eveonline.com/.well-known/oauth-authorization-server"

func NewClient(logger *zap.Logger) *APIClient {
	l := logger.Named("API")
	return &APIClient{
		logger:           l,
		configHTTPClient: durableclient.NewClient("CONFIG", "https://github.com/ferocious-space/eveapi", l.Named("CONFIG")),
		esiHTTPClient:    durableclient.NewClient("ESI", "https://github.com/ferocious-space/eveapi", l.Named("ESI")),
	}
}

func (o *APIClient) Metadata() *OAuthMetadata {
	if o.metadata == nil {
		o.metadata = new(OAuthMetadata)
		rsp, err := o.configHTTPClient.Get(MetadataURL)
		if err != nil {
			o.logger.Error("https://login.eveonline.com/.well-known/oauth-authorization-server", zap.Error(err))
			o.metadata = nil
			return nil
		}
		defer rsp.Body.Close()
		if err := jsoniter.NewDecoder(rsp.Body).Decode(&o.metadata); err != nil {
			o.logger.Error("unable to parse oauth2 metadata", zap.Error(err))
			o.metadata = nil
			return nil
		}
	}
	return o.metadata
}

func (o *APIClient) getJwkKeys() *jwk.Set {
	if o.jwkKeys == nil {
		rsp, err := o.configHTTPClient.Get(o.Metadata().JwksURI)
		if err != nil {
			o.logger.Error("unable to fetch JWK Set", zap.Error(err))
			o.jwkKeys = nil
			return nil
		}
		defer rsp.Body.Close()
		buf, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			o.logger.Error("unable to read JWK Set", zap.Error(err))
			o.jwkKeys = nil
			return nil
		}
		if o.jwkKeys, err = jwk.Parse(buf); err != nil {
			o.logger.Error("unable to decode JWK Set", zap.Error(err))
			o.jwkKeys = nil
			return nil
		}
	}
	return o.jwkKeys
}

func (o *APIClient) makeValidator() func(*jwt.Token) (interface{}, error) {
	if o.validator == nil {
		o.validator = func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, jwt.ErrInvalidKeyType
			}
			if claims, ok := t.Claims.(jwt.MapClaims); !ok {
				return nil, jwt.NewValidationError("invalid claims", jwt.ValidationErrorMalformed)
			} else {
				if err := claims.Valid(); err != nil {
					return nil, err
				}
				if !claims.VerifyIssuer(o.metadata.Issuer, true) {
					return nil, jwt.NewValidationError("invalid iss", jwt.ValidationErrorIssuer)
				}
			}
			keys := o.getJwkKeys()
			if keys == nil {
				return nil, jwt.NewValidationError("token unverifiable", jwt.ValidationErrorUnverifiable)
			}
			if key := o.getJwkKeys().LookupKeyID(t.Header["kid"].(string)); len(key) == 1 {
				return key[0].Materialize()
			}
			return nil, jwt.NewValidationError("token unverifiable", jwt.ValidationErrorUnverifiable)
		}
	}
	return o.validator
}

func (o *APIClient) config(config Config, scopes ...string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: config.Key,
		Endpoint: oauth2.Endpoint{
			AuthURL:   o.Metadata().AuthorizationEndpoint,
			TokenURL:  o.Metadata().TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: config.Callback,
		Scopes:      scopes,
	}
}

// Creates SSO client for ESISSO
func (o *APIClient) SSO(store tokenstores.TokenStore, Character string, config Config, scopes ...string) *SSO {
	return NewSSO(
		store,
		Character,
		o.config(config, scopes...),
		o.logger.Named("SSO"), o.makeValidator(),
	)
}

// Creates SSO client for ESISSO , opens a browser for unknown/invalid keys
func (o *APIClient) SSOBrowser(store tokenstores.TokenStore, Character string, config Config, scopes ...string) *SSO {
	client := o.SSO(store, Character, config, scopes...)
	_, err := client.Token()
	if err != nil {
		r := mux.NewRouter()
		u, err := url.Parse(config.Callback)
		if err != nil {
			o.logger.Fatal("unable to parse callback url", zap.Error(err))
		}
		stopchannel := make(chan struct{}, 1)
		o.logger.Sugar().Infof("Serving on %s:%s %s", u.Hostname(), u.Port(), u.Path)
		r.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
			code := r.FormValue("code")
			state := r.FormValue("state")
			encoder := json.NewEncoder(w)
			if !client.ValidState(state) {
				w.WriteHeader(http.StatusMisdirectedRequest)
				stopchannel <- struct{}{}
				return
			}
			o.logger.Info("Exchange code", zap.String("code", code))
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			token, err := client.ExchangeCode(ctx, code)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = encoder.Encode(err)
				stopchannel <- struct{}{}
				return
			}
			o.logger.Info("AccessToken Received", zap.String("token", token.AccessToken))
			if err := client.Save(token); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = encoder.Encode(err)
				stopchannel <- struct{}{}
				return
			}
			t, err := client.Token()
			if err != nil {
				_ = encoder.Encode(err)
			} else {
				_ = encoder.Encode(t)
			}
			stopchannel <- struct{}{}
		})
		hs := &http.Server{Addr: fmt.Sprintf("%s:%s", u.Hostname(), u.Port()), Handler: r}
		ctx, cancel := context.WithTimeout(context.TODO(), 15*time.Second)
		defer cancel()
		go func() {
			if err := hs.ListenAndServe(); err != http.ErrServerClosed {
				o.logger.Fatal("internal server error", zap.Error(err))
			}
		}()
		var oserr error
		authUrl := client.AuthURL()
		switch goruntime.GOOS {
		case "linux":
			oserr = exec.Command("xdg-open", authUrl).Start()
		case "windows":
			oserr = exec.Command("rundll32", "url.dll,FileProtocolHandler", authUrl).Start()
		case "darwin":
			oserr = exec.Command("open", authUrl).Start()
		default:
			oserr = fmt.Errorf("unsupported platform")
		}
		if oserr != nil {
			o.logger.Fatal("Unable to execute browser.", zap.Error(err))
		}
		select {
		case <-stopchannel:
			err = hs.Shutdown(ctx)
			if err != nil {
				o.logger.Fatal("Error stopping webserver.", zap.Error(err))
			}
		case <-ctx.Done():
			err = hs.Shutdown(ctx)
			if err != nil {
				o.logger.Fatal("Error stopping webserver.", zap.Error(err))
			}
		}
	}
	return client
}

// Creates Client for ESI endpoints
func (o *APIClient) ESI(cache httpcache.Cache, auth ...*SSO) *esi.EVESwaggerInterface {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		o.logger.Named("MetaClient").Error("unable to create cookiejar", zap.Error(err))
		return nil
	}
	var CLITransport http.RoundTripper
	if cache != nil {
		cT := httpcache.NewTransport(cache)
		cT.Transport = o.esiHTTPClient.Transport
		CLITransport = cT
	} else {
		cT := httpcache.NewTransport(httpcache.NewLRUCache(1<<20*256, 300))
		cT.Transport = o.esiHTTPClient.Transport
		CLITransport = cT
	}

	rt := httptransport.NewWithClient(esi.DefaultHost, esi.DefaultBasePath, esi.DefaultSchemes, &http.Client{
		Transport:     CLITransport,
		CheckRedirect: nil,
		Jar:           jar,
	})

	rt.Producers[runtime.JSONMime] = runtime.ProducerFunc(func(writer io.Writer, data interface{}) error {
		enc := jsoniter.NewEncoder(writer)
		enc.SetEscapeHTML(false)
		return enc.Encode(data)
	})

	rt.Consumers[runtime.JSONMime] = runtime.ConsumerFunc(func(reader io.Reader, data interface{}) error {
		dec := jsoniter.NewDecoder(reader)
		dec.UseNumber()
		return dec.Decode(data)
	})
	if len(auth) == 1 {
		rt.DefaultAuthentication = auth[0].AuthInfoWriter()
	}
	return esi.New(rt, strfmt.Default)
}
