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

package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"golang.org/x/oauth2"
)

func SetEndpointUrl(rawText string) error {
	verified, err := verifyUrl(rawText)
	if err != nil {
		return err
	}

	c, save, err := ReadWriteConfig()
	if err != nil {
		return err
	}

	c.Url = verified

	return save()
}

func SetServices(services []*Service) error {
	c, save, err := ReadWriteConfig()
	if err != nil {
		return err
	}

	c.Services = services
	return save()
}

func SetAccounts(accounts []*Account, s int) error {
	c, save, err := ReadWriteConfig()
	if err != nil {
		return err
	}

	c.Services[s].Accounts = accounts
	return save()
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func NewServiceUpdater(previousName string) (*ServiceUpdater, error) {
	c, save, err := ReadWriteConfig()
	if err != nil {
		return nil, err
	}

	return &ServiceUpdater{
		c:            c,
		previousName: previousName,
		save:         save,
	}, nil
}

type ServiceUpdater struct {
	previousName                                    string
	name, clientID, clientSecret, authURL, tokenURL *string
	scopes                                          *[]string
	save                                            func() error
	c                                               *Config
}

func (u *ServiceUpdater) Commit() error {
	var s *Service

	if u.previousName == "" {
		s = &Service{
			OauthServiceCreds: &OauthServiceCreds{},
		}
		u.c.Services = append(u.c.Services, s)
	} else {
		for _, other := range u.c.Services {
			if other.ServiceName == u.previousName {
				s = other
			}
		}
	}
	if s == nil {
		return errors.New("Unable to find service, was its name changed while editing?")
	}

	if u.name != nil {
		s.ServiceName = *u.name
	}
	if u.clientID != nil {
		s.OauthServiceCreds.ClientID = *u.clientID
	}
	if u.clientSecret != nil {
		s.OauthServiceCreds.ClientSecret = *u.clientSecret
	}
	if u.authURL != nil {
		s.OauthServiceCreds.AuthURL = *u.authURL
	}
	if u.tokenURL != nil {
		s.OauthServiceCreds.TokenURL = *u.tokenURL
	}
	if u.scopes != nil {
		s.OauthServiceCreds.Scopes = *u.scopes
	}

	return u.save()
}

func (u *ServiceUpdater) Name(name string) error {
	err := verifyName(name)
	if err != nil {
		return err
	}

	if name != u.previousName {
		for _, other := range u.c.Services {
			if name == other.ServiceName {
				return errors.New("That service name is already in use.  Choose another.")
			}
		}
	}

	u.name = &name
	return nil
}

func (u *ServiceUpdater) ClientID(clientID string) error {
	if clientID == "" {
		return errors.New("Client ID cannot be empty.")
	}

	u.clientID = &clientID
	return nil
}

func (u *ServiceUpdater) ClientSecret(clientSecret string) error {
	if clientSecret == "" {
		return errors.New("Client Secret cannot be empty.")
	}

	u.clientSecret = &clientSecret
	return nil
}

func (u *ServiceUpdater) AuthURL(authURL string) error {
	verified, err := verifyUrl(authURL)
	if err != nil {
		return err
	}

	u.authURL = &verified
	return nil
}

func (u *ServiceUpdater) TokenURL(tokenURL string) error {
	verified, err := verifyUrl(tokenURL)
	if err != nil {
		return err
	}

	u.tokenURL = &verified
	return nil
}

func (u *ServiceUpdater) Scopes(scopes string) error {
	list := strings.Split(scopes, ",")
	output := make([]string, 0)

	for _, input := range list {
		scope := strings.TrimSpace(input)
		if scope != "" {
			output = append(output, scope)
		}
	}

	u.scopes = &output
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func NewAccountUpdater(previousName string, newCreds bool, s int) (*AccountUpdater, error) {
	c, save, err := ReadWriteConfig()
	if err != nil {
		return nil, err
	}

	return &AccountUpdater{
		c:            c,
		s:            s,
		previousName: previousName,
		newCreds:     newCreds,
		save:         save,
	}, nil
}

type AccountUpdater struct {
	previousName     string
	name, serviceURL *string
	oauthCreds       *oauth2.Token
	newCreds         bool
	save             func() error
	s                int
	c                *Config
}

func (u *AccountUpdater) Commit() error {
	var a *Account

	if u.previousName == "" {
		a = &Account{
			ClientCreds: &ClientCreds{},
		}
		u.c.Services[u.s].Accounts = append(u.c.Services[u.s].Accounts, a)
	} else {
		for _, other := range u.c.Services[u.s].Accounts {
			if other.AccountName == u.previousName {
				a = other
			}
		}
	}
	if a == nil {
		return errors.New("Unable to find account, was its name changed while editing?")
	}

	if u.name != nil {
		a.AccountName = *u.name
	}

	if u.serviceURL != nil {
		a.ServiceURL = *u.serviceURL
	}

	if u.newCreds {
		a.ClientCreds.generateClientCreds()
		fmt.Printf("Generating new access credentials, privkey: %s, protocol: %s \n",
			a.ClientCreds.PrivateKey, a.ClientCreds.Protocol)
	}

	if u.oauthCreds != nil {
		a.OauthAccountCreds = u.oauthCreds
	}
	return u.save()
}

func (u *AccountUpdater) Name(name string) error {
	// verifyName() not required for UI path
	err := verifyName(name)
	if err != nil {
		return err
	}

	if name != u.previousName {
		for _, other := range u.c.Services[u.s].Accounts {
			if name == other.AccountName {
				return errors.New("That account name is already in use.  Choose another.")
			}
		}
	}

	u.name = &name
	return nil
}

func (u *AccountUpdater) ServiceURL(serviceURL string) error {
	verified, err := verifyUrl(serviceURL)
	if err != nil {
		return err
	}

	u.serviceURL = &verified
	return nil
}

func (u *AccountUpdater) OauthCreds(code string) error {
	oauthConf := getOauthConfig(u.c.Url, u.c.Services[u.s])
	token, err := oauthConf.Exchange(context.Background(), code)
	if err != nil {
		return err
	}

	u.oauthCreds = token
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func CreateAccountKey(c *Config, s *Service, a *Account) (string, error) {
	j := struct {
		WebGatewayUrl string
		Protocol      string
		PrivateKey    string
	}{
		WebGatewayUrl: c.Url,
		Protocol:      a.ClientCreds.Protocol,
		PrivateKey:    a.ClientCreds.PrivateKey,
	}

	b, err := json.Marshal(j)
	if err != nil {
		return "", err
	}

	inner := base64.StdEncoding.EncodeToString(b)

	return fmt.Sprintf("KEYBEGIN_%s/%s_%s_KEYEND", s.ServiceName, a.AccountName, inner), nil
}

func GenerateAuthUrl(url string, s *Service) (string, string, error) {
	oauthConf := getOauthConfig(url, s)
	state, err := generateRandomString()
	if err != nil {
		return "", "", fmt.Errorf("Problem with random number generation.  Can't continue.\n")
	}
	return oauthConf.AuthCodeURL(state), state, nil
}

func VerifyState(code string, state string) (string, error) {
	jsonAuthCode, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return "", fmt.Errorf("Bad decode.\n")
	}
	j := struct {
		Token string
		State string
	}{}
	json.Unmarshal(jsonAuthCode, &j)
	if j.State != state {
		return "", fmt.Errorf("Bad state. Expected %s, got %s\n", state, j.State)
	}
	return j.Token, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func verifyName(rawText string) error {
	if rawText == "" {
		return errors.New("Name cannot be empty.")
	}

	match, _ := regexp.MatchString("^[-a-z0-9]+$", rawText)
	if !match {
		return errors.New("That name contains invalid characters.")
	}
	return nil
}

func verifyUrl(rawText string) (string, error) {
	tokenURL, err := url.ParseRequestURI(rawText)
	if err != nil {
		return "", errors.New(rawText + " is not a valid URL (include https://)")
	}
	if tokenURL.Scheme != "https" {
		return "", errors.New(rawText + " does not use https.")
	}

	return tokenURL.String(), nil
}

func getOauthConfig(url string, s *Service) *oauth2.Config {
	var endpoint = oauth2.Endpoint{
		AuthURL:  s.OauthServiceCreds.AuthURL,
		TokenURL: s.OauthServiceCreds.TokenURL,
	}
	oauthConf := &oauth2.Config{
		ClientID:     s.OauthServiceCreds.ClientID,
		ClientSecret: s.OauthServiceCreds.ClientSecret,
		Scopes:       s.OauthServiceCreds.Scopes,
		Endpoint:     endpoint,
		RedirectURL:  getRedirectUrl(url),
	}
	return oauthConf
}

func getRedirectUrl(address string) string {
	redirectUrl, err := url.Parse(address)
	if err != nil {
		fmt.Println("Web-Api-Gatway url setting is invalid, can't continue.")
		return ""
	}
	redirectUrl.Path = "/authToken/"
	return redirectUrl.String()
}

func generateRandomString() (string, error) {
	b := make([]byte, 30)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func (creds *ClientCreds) generateClientCreds() {
	fmt.Println("Generating new secret for client credentials.")
	for i := 0; i < 10; i++ {

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println("error generating key: ", err)
			fmt.Println("Trying again")
			continue
		}

		bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			fmt.Println("error marshling key: ", err)
			fmt.Println("Trying again")
			continue
		}

		creds.Protocol = "ECDSA_SHA256_PKCS8_V1"
		creds.PrivateKey = base64.StdEncoding.EncodeToString(bytes)
		return
	}

	fmt.Println("Too many failures trying to create client credentials, exiting without saving.")
	os.Exit(1)
}
