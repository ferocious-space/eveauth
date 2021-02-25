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

package main

import (
	"context"
	"runtime"
	"time"

	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"github.com/ferocious-space/badgerhold"
	"github.com/ferocious-space/httpcache"
	"github.com/ferocious-space/httpcache/BadgerCache"
	"github.com/go-openapi/swag"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/ferocious-space/eveapi/esi/character"
	"github.com/ferocious-space/eveapi/esi/meta"
	"github.com/ferocious-space/eveapi/esi/routes"
	"github.com/ferocious-space/eveapi/esi/universe"
	"github.com/ferocious-space/eveapi/esi/wallet"
	notification "github.com/ferocious-space/eveapi/notifications"

	"github.com/ferocious-space/eveauth"
	"github.com/ferocious-space/eveauth/tokenstores"
)

func main() {
	logger, _ := zap.NewDevelopment(zap.IncreaseLevel(zap.DebugLevel))
	cLogger := logger.Named("Client")
	apiClient := eveauth.NewClient(cLogger)

	Conf := eveauth.Config.Load(eveauth.Config{}, "config.json", cLogger.Named("config"))

	// metaClient := apiClient.Meta(nil)
	// rsp, err := metaClient.Meta.GetPing(meta.NewGetPingParams().WithContext(context.Background()).WithTimeout(5 * time.Second))
	// if err != nil {
	// 	logger.Panic("no ping to ESI", zap.Error(err))
	// }
	// logger.Info(rsp.GetPayload())

	opts := badger.DefaultOptions("./cache/testing").WithCompression(options.Snappy)
	if runtime.GOOS == "windows" {
		opts.Truncate = true
	}
	db, err := badgerhold.Open(badgerhold.Options{
		Encoder:          jsoniter.Marshal,
		Decoder:          jsoniter.Unmarshal,
		SequenceBandwith: 128,
		Options:          opts,
	})
	if err != nil {
		logger.Fatal("database open", zap.Error(err))
	}
	tokenstore := tokenstores.NewBadgerTokenStore(cLogger.Named("TOKENSTORE"), db)
	sso := apiClient.SSO(tokenstore, "Ferocious Bite", Conf, "esi-characters.read_notifications.v1", "esi-wallet.read_character_wallet.v1", "esi-skills.read_skills.v1")
	_, err = sso.Token()
	if err != nil {
		logger.Error("sso", zap.Error(err))
		sso = apiClient.SSOBrowser(tokenstore, "Ferocious Bite", Conf, "esi-characters.read_notifications.v1", "esi-wallet.read_character_wallet.v1", "esi-skills.read_skills.v1")
		_, err = sso.Token()
		if err != nil {
			logger.Panic("sso failed", zap.Error(err))
		}
	}

	sso2 := apiClient.SSO(tokenstore, "Ferocious Bite", Conf, "publicData")
	_, err = sso2.Token()
	if err != nil {
		logger.Error("sso2", zap.Error(err))
		sso2 = apiClient.SSOBrowser(tokenstore, "Ferocious Bite", Conf, "publicData")
		_, err = sso2.Token()
		if err != nil {
			logger.Panic("sso2 failed", zap.Error(err))
		}
	}
	cache := BadgerCache.NewBadgerCache(db.Badger(), sso.GetCharacter()+":cache", cLogger.Named("CACHE"))
	esi := apiClient.ESI(httpcache.NewDoubleCache(httpcache.NewLRUCache(1<<20*256, 0), cache), sso)
	rsp, err := esi.Meta.GetPing(meta.NewGetPingParams().WithTimeout(500 * time.Millisecond))
	if err != nil {
		logger.Panic("no ping to ESI", zap.Error(err))
	}
	logger.Info(rsp.GetPayload())

	res, err := esi.Character.GetCharactersCharacterIDNotifications(character.NewGetCharactersCharacterIDNotificationsParams().WithContext(context.Background()).WithCharacterID(sso.CharacterID()), sso.AuthInfoWriter())
	if err != nil {
		logger.Panic("failed to pull notifications", zap.Error(err))
	}
	for _, n := range res.GetPayload() {
		notif, err := notification.ParseNotification(n)
		if err != nil {
			logger.Panic("unknown notification", zap.Error(err))
		}
		switch d := notif.(type) {
		case *notification.StructureImpendingAbandonmentAssetsAtRisk:
			info, _ := esi.Universe.GetUniverseTypesTypeID(universe.NewGetUniverseTypesTypeIDParams().WithContext(context.Background()).WithTypeID(d.StructureTypeID))
			if info.GetPayload() != nil {
				t, _ := time.Parse(time.RFC3339Nano, n.Timestamp.String())
				if time.Until(t.Add(time.Duration(d.DaysUntilAbandon)*24*time.Hour)) > 0 {
					logger.Sugar().Infof("Time: %s, Struct: %d, Days: %d, System: %d, Link: %s, Info: %v", t.Add(time.Duration(d.DaysUntilAbandon)*24*time.Hour), d.StructureID, d.DaysUntilAbandon, d.SolarsystemID, d.StructureLink, swag.StringValue(info.GetPayload().Name))
				}
			}
		case *notification.StructureItemsDelivered:
			logger.Sugar().Infof("Char: %d Structure: %d items: %v", d.CharID, d.StructureID, d.ListOfTypesAndQty)
		default:
		}
	}
	res2, err := esi.Universe.GetUniverseConstellationsConstellationID(universe.NewGetUniverseConstellationsConstellationIDParams().WithContext(context.Background()).WithConstellationID(21000240))
	if err != nil {
		logger.Panic("failed constellationID", zap.Error(err))
	}

	jour, err := esi.Wallet.GetCharactersCharacterIDWalletJournal(wallet.NewGetCharactersCharacterIDWalletJournalParams().WithContext(context.Background()).WithCharacterID(sso.CharacterID()), sso.AuthInfoWriter())
	if err != nil {
		logger.Panic("failed route", zap.Error(err))
	}
	for _, pl := range jour.GetPayload() {
		_ = pl.ID
	}
	logger.Info(swag.StringValue(res2.GetPayload().Name))
	logger.Info("starting 5 second refresher test")
	_, err = esi.Routes.GetRouteOriginDestination(routes.NewGetRouteOriginDestinationParams().WithContext(context.Background()).WithOrigin(30000142).WithDestination(30003135).WithConnections([][]int32{{30003870, 30003871}}))
	if err != nil {
		logger.Panic("failed route", zap.Error(err))
	}
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ticker.C:
			go func() {
				_, err := sso.Token()
				if err != nil {
					panic(err)
				}
			}()
			go func() {
				_, err = sso2.Token()
				if err != nil {
					panic(err)
				}
			}()
			go func() {
				_, err := sso.Token()
				if err != nil {
					panic(err)
				}
			}()
			go func() {
				_, err = sso2.Token()
				if err != nil {
					panic(err)
				}
			}()
			go func() {
				_, err := sso.Token()
				if err != nil {
					panic(err)
				}
			}()
			go func() {
				_, err = sso2.Token()
				if err != nil {
					panic(err)
				}
			}()
		}
	}
}
