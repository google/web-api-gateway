/*
Copyright 2019 Google LLC

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

// Package config provides the config details for the services.
package config

import (
	"golang.org/x/oauth2"
)

// Config is the root for configuration of the web-api-gateway.
type Config struct {
	Url      string
	Users    map[string]bool // user whitelist
	Services []*Service
	Template Template
}

// Service represents a distinct endpoint that can contain multiple account.
type Service struct {
	ServiceName       string // name for reference when setting up an account
	OauthServiceCreds *OauthServiceCreds
	Accounts          []*Account
	EngineName        string
}

// OauthServiceCreds stores the information to get authorized to connect new
// accounts.
type OauthServiceCreds struct {
	ClientID     string   // public identifier
	ClientSecret string   // secret identifier
	AuthURL      string   // authenticaiton endpoint
	TokenURL     string   // token request endpoint
	Scopes       []string // scopes of the requests
}

// Account stores the account name and the credential details for connections
// to/from the web-api-gateway.
type Account struct {
	AccountName       string // name for this account
	ServiceURL        string // service endpoint to be connected
	OauthAccountCreds *oauth2.Token
	ClientCreds       *ClientCreds
}

// ClientCreds stores the autorization details to connect to this account.
type ClientCreds struct {
	Protocol   string // rule for encrypting messages
	PrivateKey string // key for encrypting messages
}

type Template struct {
	Engines []*Engine
}

type Engine struct {
	EngineName string
	AuthURL    string
	TokenURL   string
	Scopes     string
	Domains    []*Domain
}

type Domain struct {
	DomainName string
	ServiceURL string
}
