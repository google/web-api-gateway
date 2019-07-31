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
	"errors"
	"net/url"
	"regexp"
	"strings"
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
	accounts																				[]*Account
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
	if u.accounts != nil {
		s.Accounts = u.accounts
	}

	return u.save()
}

func (u *ServiceUpdater) Account(idx int, account *Account) error {
	// log.Printf("!! %d", idx)
	u.accounts[idx] = account
	return nil
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
