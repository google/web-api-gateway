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

const version = "0.3"

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
	http.HandleFunc("/authToken/", authTokenPage)

	logger := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Incoming Request %s %s %s", r.RemoteAddr, r.Method, r.URL)
		http.DefaultServeMux.ServeHTTP(w, r)
	})

	log.Println("Starting server...")
	log.Fatal(http.ListenAndServeTLS(*addr, *certFile, *keyFile, logger))
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
			path, handler, err := createAccountHandler(c, service, account)
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

func createAccountHandler(c *config.Config, service *config.Service, account *config.Account) (string, http.Handler, error) {
	// TODO: we're assuming that service and account names are valid.  The editing tool validates this
	// but it should be validated when loading too.
	basePath := fmt.Sprintf("/service/%s/account/%s/", service.ServiceName, account.AccountName)
	mux := http.NewServeMux()

	modifyResponse, err := createModifyResponse(c.Url, basePath)
	if err != nil {
		return "", nil, err
	}

	{
		handler, err := createOAuthForwarder(service, account, modifyResponse)
		if err != nil {
			return "", nil, err
		}
		mux.Handle(basePath+"forward/", http.StripPrefix(basePath+"forward/", handler))
	}

	mux.Handle(basePath+"authlessForward/", authlessForward(modifyResponse))

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

func createModifyResponse(gatewayUrl, basePath string) (func(*http.Response) error, error) {
	if _, err := url.Parse(gatewayUrl); err != nil {
		return nil, err
	}

	return func(r *http.Response) error {
		if r.StatusCode >= 300 && r.StatusCode < 400 {
			location := r.Header.Get("Location")

			v := url.Values{}
			v.Set("url", location)

			newLocation, _ := url.Parse(gatewayUrl)
			newLocation.Path = basePath + "authlessForward/"
			newLocation.RawQuery = v.Encode()

			r.Header.Set("Location", newLocation.String())
		}
		return nil
	}, nil
}

func createOAuthForwarder(service *config.Service, account *config.Account, modifyResponse func(*http.Response) error) (http.Handler, error) {
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
	proxy.ModifyResponse = modifyResponse

	fixRequest := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ClientIdHeader := r.Header.Get("For-Web-Api-Gateway-ClientID-Header")
		if ClientIdHeader != "" {
			r.Header.Add(ClientIdHeader, service.OauthServiceCreds.ClientID)
		}

		adjustRequest(r, domain)

		proxy.ServeHTTP(w, r)
	})

	return fixRequest, err
}

func adjustRequest(r *http.Request, domain *url.URL) {
	headersToRemove := []string{"User-Agent"}
	for header := range r.Header {
		if strings.HasPrefix(header, "For-Web-Api-Gateway") {
			headersToRemove = append(headersToRemove, header)
		}
	}
	for _, header := range headersToRemove {
		r.Header.Del(header)
	}

	r.RemoteAddr = ""
	r.Host = domain.Host

}

func authlessForward(modifyResponse func(*http.Response) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		var err error
		r.URL, err = url.Parse(r.FormValue("url"))
		if err != nil {
			ErrorParsingRedirectUrl.ServeHTTP(w, r)
			return
		}

		domain := url.URL{
			Scheme: r.URL.Scheme,
			Host:   r.URL.Host,
		}

		adjustRequest(r, &domain)

		proxy := httputil.NewSingleHostReverseProxy(&domain)
		proxy.ModifyResponse = modifyResponse

		proxy.ServeHTTP(w, r)
	})
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

func authTokenPage(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	response := struct {
		Token string
		State string
	}{
		Token: r.FormValue("code"),
		State: r.FormValue("state"),
	}

	b, err := json.Marshal(response)
	if err != nil {
		w.Write([]byte("Error generating response.  It has been logged."))
		log.Println("Error generating authToken response:", err)
		return
	}

	s := "Copy-paste this code into the setup tool: " + base64.StdEncoding.EncodeToString(b)

	_, err = w.Write([]byte(s))
	if err != nil {
		w.Write([]byte("Error generating response.  It has been logged."))
		log.Println("Error generating authToken response:", err)
		return
	}
}
