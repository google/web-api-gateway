/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strings"
	"time"
	"web-api-gateway/config"

	"golang.org/x/oauth2"
)

const version = "0.2"

var certFile *string = flag.String(
	"certFile",
	"/etc/webapigateway/cert/fullchain.pem",
	"This is the full public certificate for this web server.",
)

var keyFile *string = flag.String(
	"keyFile",
	"/etc/webapigateway/cert/privkey.pem",
	"This is the private key for the certFile.",
)

var addr *string = flag.String(
	"addr",
	":443",
	"This is the address:port which the server listens to.",
)

func main() {
	flag.Parse()

	log.Println("Reading config file...")

	http.Handle("/service/", createConfigHandler())

	log.Println("Starting server...")
	log.Fatal(http.ListenAndServeTLS(*addr, *certFile, *keyFile, nil))
}

func createConfigHandler() http.Handler {
	c, err := config.ReadConfig()
	if err != nil {
		log.Printf("Error reading config file: %s", err)
		return ErrorReadingConfig
	}

	mux := http.NewServeMux()
	for _, service := range c.Services {
		for _, account := range service.Accounts {
			path, handler, err := createAccountHandler(service, account)
			if err != nil {
				log.Printf(
					"Error reading the config, service: %s, account: %s, error: %s",
					service.ServiceName,
					account.AccountName,
					err)
				return ErrorReadingConfig
			}
			mux.Handle(path, handler)
		}
	}

	return mux
}

func createAccountHandler(service *config.Service, account *config.Account) (string, http.Handler, error) {
	// TODO: we're assuming that service and account names are valid.  The editing tool validates this
	// but it should be validated when loading too.
	basePath := fmt.Sprintf("/service/%s/account/%s/", service.ServiceName, account.AccountName)
	mux := http.NewServeMux()

	{
		handler, err := createOAuthForwarder(service, account)
		if err != nil {
			return "", nil, err
		}
		mux.Handle(basePath+"forward/", http.StripPrefix(basePath+"forward/", handler))
	}

	mux.Handle(basePath+"status", createStatusPage(service, account))

	handler, err := wrapWithClientAuth(mux, account)
	if err != nil {
		return "", nil, err
	}
	return basePath, handler, nil
}

func wrapWithClientAuth(handler http.Handler, account *config.Account) (http.Handler, error) {
	// TODO TEST account.ClientCreds.Protocol and ensure it's what we're expecting here.

	der, err := base64.StdEncoding.DecodeString(account.ClientCreds.PrivateKey)
	if err != nil {
		// Don't log error details in case they include info on the secret.
		return nil, errors.New("error decoding private key from base64")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// Don't log error details in case they include info on the secret.
		return nil, errors.New("error parsing private key")
	}

	switch privateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return onlyAllowVerifiedRequests(handler, &privateKey.PublicKey, time.Now), nil
	}
	return nil, errors.New("Private key not of type ecdsa")
}

func createOAuthForwarder(service *config.Service, account *config.Account) (http.Handler, error) {
	var endpoint = oauth2.Endpoint{
		AuthURL:  service.OauthServiceCreds.AuthURL,
		TokenURL: service.OauthServiceCreds.TokenURL,
	}

	oauthConf := &oauth2.Config{
		ClientID:     service.OauthServiceCreds.ClientID,
		ClientSecret: service.OauthServiceCreds.ClientSecret,
		Scopes:       service.OauthServiceCreds.Scopes,
		Endpoint:     endpoint,
	}

	transport := &oauth2.Transport{
		Source: oauthConf.TokenSource(context.Background(), account.OauthAccountCreds),
	}

	domain, err := url.Parse(account.ServiceURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(domain)
	proxy.Transport = transport

	fixRequest := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ClientIdHeader := r.Header.Get("For-Web-Api-Gateway-ClientID-Header")

		headersToRemove := []string{"User-Agent"}
		for header := range r.Header {
			if strings.HasPrefix(header, "For-Web-Api-Gateway") {
				headersToRemove = append(headersToRemove, header)
			}
		}
		for _, header := range headersToRemove {
			r.Header.Del(header)
		}
		if ClientIdHeader != "" {
			r.Header.Add(ClientIdHeader, service.OauthServiceCreds.ClientID)
		}

		r.RemoteAddr = ""
		r.Host = domain.Host
		proxy.ServeHTTP(w, r)
	})

	return fixRequest, err
}

func createStatusPage(service *config.Service, account *config.Account) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := struct {
			Version    string
			GoVersion  string
			TokenUrl   string
			AuthUrl    string
			Scopes     []string
			ServiceUrl string
		}{
			Version:    version,
			GoVersion:  runtime.Version(),
			AuthUrl:    service.OauthServiceCreds.AuthURL,
			TokenUrl:   service.OauthServiceCreds.TokenURL,
			Scopes:     service.OauthServiceCreds.Scopes,
			ServiceUrl: account.ServiceURL,
		}

		b, err := json.Marshal(status)
		if err != nil {
			ErrorEncodingStatusJson.ServeHTTP(w, r)
			return
		}

		_, err = w.Write(b)
		if err != nil {
			ErrorIO.ServeHTTP(w, r)
			return
		}
	})
}
