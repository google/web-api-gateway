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

// The command line tool for setting up services and accounts.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"web-api-gateway/config"

	"golang.org/x/oauth2"
)

func main() {
	flag.Parse()
	fmt.Printf("Welcome to the Web Api Gateway Config Tool.\n\n")

	term := newRealTerminal()

	c, save, err := config.ReadWriteConfig()
	if err != nil {
		fmt.Printf("Unable to load config file: %v\n", err)
		os.Exit(1)
	}

	configEditor{c}.edit(term)

	fmt.Println("Saving...")
	for {
		err = save()
		if err == nil {
			fmt.Println("Save successful!")
			fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			fmt.Println("Remember to restart the server.")
			fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			return
		}
		fmt.Printf("There was an error saving the config file: %v\n", err)
		tryAgain := term.readBoolean("Do you want to try again? (no to lose all changes and exit.)")
		if !tryAgain {
			return
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type configEditor struct {
	c *config.Config
}

func (e configEditor) edit(term *terminal) {
	if e.c.Url == "" {
		e.editUrl(term)
	}

	takeActionLoop(term,
		newAction("Retrieve Account Key", e.retrieveAccountKey),
		newAction("Edit Web Api Gateway Url", e.editUrl),
		newAction("Add service", e.addService),
		newAction("Edit service (including adding new accounts to an existing service)", e.editService),
		newAction("Delete service", e.removeService))
}

func (e configEditor) editUrl(term *terminal) {
	e.c.Url = term.readUrl("Web Api Gateway Url")
}

func (e configEditor) addService(term *terminal) {
	s := &config.Service{}
	serviceEditor{e.c, s}.newSetup(term)
	e.c.Services = append(e.c.Services, s)
}

func (e configEditor) editService(term *terminal) {
	if len(e.c.Services) == 0 {
		fmt.Println("There are no services to edit.")
		return
	}

	fmt.Println("Services:")

	namer := func(i int) string { return e.c.Services[i].ServiceName }
	i := term.readChoice(namer, len(e.c.Services))

	serviceEditor{e.c, e.c.Services[i]}.edit(term)
}

func (e configEditor) removeService(term *terminal) {
	if len(e.c.Services) == 0 {
		fmt.Println("There are no services to delete.")
		return
	}

	fmt.Println("Services:")

	namer := func(i int) string { return e.c.Services[i].ServiceName }
	i := term.readChoice(namer, len(e.c.Services))

	e.c.Services = append(e.c.Services[:i], e.c.Services[i+1:]...)
}

func (e configEditor) retrieveAccountKey(term *terminal) {
	fmt.Println("Select which account:")

	type accountSpecific struct {
		s *config.Service
		a *config.Account
	}

	allAccounts := make([]accountSpecific, 0)

	for _, s := range e.c.Services {
		for _, a := range s.Accounts {
			allAccounts = append(allAccounts, accountSpecific{s, a})
		}
	}

	if len(allAccounts) == 0 {
		fmt.Println("You must create accounts first!")
		return
	}

	namer := func(i int) string {
		return allAccounts[i].s.ServiceName + "/" + allAccounts[i].a.AccountName
	}
	i := term.readChoice(namer, len(allAccounts))

	key, err := createAccountKey(e.c, allAccounts[i].s, allAccounts[i].a)
	if err != nil {
		fmt.Println("Error creating account key:")
		fmt.Println(err)
		return
	}
	fmt.Println()
	fmt.Println("Copy and paste everything from (and including) KEYBEGIN to KEYEND")
	fmt.Println()
	fmt.Println(key)
	fmt.Println()
	fmt.Println()
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func createAccountKey(c *config.Config, s *config.Service, a *config.Account) (string, error) {
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

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type serviceEditor struct {
	c *config.Config
	s *config.Service
}

func (e serviceEditor) newSetup(term *terminal) {
	e.setName(term)
	e.s.OauthServiceCreds = new(config.OauthServiceCreds)
	oauthServiceCredsEditor{e.s.OauthServiceCreds}.newSetup(term)
	e.edit(term) // Give user chance to add accounts right away
}

func (e serviceEditor) edit(term *terminal) {
	takeActionLoop(term,
		newAction("Edit name", confirmRename(e.setName)),
		newAction("Edit OAuth credentials", (&oauthServiceCredsEditor{e.s.OauthServiceCreds}).edit),
		newAction("Add new account", e.addAccount),
		newAction("Edit account", e.editAccount),
		newAction("Remove account", e.removeAccount))
}

func (e serviceEditor) setName(term *terminal) {
	e.s.ServiceName = ""
OUTER:
	for {
		name := term.readName()

		for _, other := range e.c.Services {
			if name == other.ServiceName {
				fmt.Println("That service name is already in use.  Choose another.")
				continue OUTER
			}
		}
		e.s.ServiceName = name
		return
	}
}

func (e serviceEditor) addAccount(term *terminal) {
	a := &config.Account{}
	wasSuccess := accountEditor{e.c, e.s, a}.newSetup(term)

	if wasSuccess {
		e.s.Accounts = append(e.s.Accounts, a)
	} else {
		fmt.Println("Could not add account.")
	}
}

func (e serviceEditor) editAccount(term *terminal) {
	if len(e.s.Accounts) == 0 {
		fmt.Println("There are no accounts to edit.")
		return
	}

	fmt.Println("Accounts:")

	namer := func(i int) string { return e.s.Accounts[i].AccountName }
	i := term.readChoice(namer, len(e.s.Accounts))

	accountEditor{e.c, e.s, e.s.Accounts[i]}.edit(term)
}

func (e serviceEditor) removeAccount(term *terminal) {
	if len(e.s.Accounts) == 0 {
		fmt.Println("There are no accounts to delete.")
		return
	}

	fmt.Println("Accounts:")

	namer := func(i int) string { return e.s.Accounts[i].AccountName }
	i := term.readChoice(namer, len(e.s.Accounts))

	e.s.Accounts = append(e.s.Accounts[:i], e.s.Accounts[i+1:]...)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type oauthServiceCredsEditor struct {
	o *config.OauthServiceCreds
}

func (e oauthServiceCredsEditor) newSetup(term *terminal) {
	e.setClientId(term)
	e.setClientSecret(term)
	e.setAuthURL(term)
	e.setTokenURL(term)
	e.setScopes(term)
}

func (e oauthServiceCredsEditor) edit(term *terminal) {
	takeActionLoop(term,
		newAction("Edit Client Id", e.setClientId),
		newAction("Edit Client Secret", e.setClientSecret),
		newAction("Edit Auth Url", e.setAuthURL),
		newAction("Edit Token Url", e.setTokenURL),
		newAction("Edit Scopes", e.setScopes),
	)
}

func (e oauthServiceCredsEditor) setClientId(term *terminal) {
	fmt.Printf("Enter the client id> ")
	e.o.ClientID = term.readSimpleString()
}

func (e oauthServiceCredsEditor) setClientSecret(term *terminal) {
	fmt.Printf("Enter the client secret> ")
	e.o.ClientSecret = term.readSimpleString()
}

func (e oauthServiceCredsEditor) setAuthURL(term *terminal) {
	e.o.AuthURL = term.readUrl("Auth URL")
}

func (e oauthServiceCredsEditor) setTokenURL(term *terminal) {
	e.o.TokenURL = term.readUrl("Token URL")
}

func (e oauthServiceCredsEditor) setScopes(term *terminal) {
	fmt.Printf("Enter scopes (comma seperated)> ")
	e.o.Scopes = term.readStringList()
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type accountEditor struct {
	c *config.Config
	s *config.Service
	a *config.Account
}

func (e accountEditor) newSetup(term *terminal) bool {
	e.setName(term)
	e.setServiceUrl(term)
	e.generateNewClientCreds(term)
	return e.generateNewOauthAccountCreds(term)
}

func (e accountEditor) edit(term *terminal) {
	takeActionLoop(term,
		newAction("Edit Name", confirmRename(e.setName)),
		newAction("Edit Service Url", e.setServiceUrl),
		newAction("Generate New Client Credentials", confirmNewClientCredentials(e.generateNewClientCreds)),
		newAction("Reauthorize account", func(t *terminal) { e.generateNewOauthAccountCreds(t) }),
	)
}

func (e accountEditor) setName(term *terminal) {
	e.a.AccountName = ""

OUTER:
	for {
		name := term.readName()

		for _, other := range e.s.Accounts {
			if name == other.AccountName {
				fmt.Println("That service name is already in use.  Choose another.")
				continue OUTER
			}
		}
		e.a.AccountName = name
		return
	}
}

func (e accountEditor) setServiceUrl(term *terminal) {
	e.a.ServiceURL = term.readUrl("Service URL")
}

func (e accountEditor) generateNewClientCreds(term *terminal) {
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

		creds := config.ClientCreds{
			Protocol:   "ECDSA_SHA256_PKCS8_V1",
			PrivateKey: base64.StdEncoding.EncodeToString(bytes),
		}

		e.a.ClientCreds = &creds
		return
	}
	fmt.Println("Too many failures trying to create client credentials, exiting without saving.")
	os.Exit(1)

}

func (e accountEditor) generateNewOauthAccountCreds(term *terminal) bool {
	var endpoint = oauth2.Endpoint{
		AuthURL:  e.s.OauthServiceCreds.AuthURL,
		TokenURL: e.s.OauthServiceCreds.TokenURL,
	}

	redirectUrl, err := url.Parse(e.c.Url)
	if err != nil {
		fmt.Println("Web-Api-Gatway url setting is invalid, can't continue.")
		return false
	}
	redirectUrl.Path = "/authToken/"

	oauthConf := &oauth2.Config{
		ClientID:     e.s.OauthServiceCreds.ClientID,
		ClientSecret: e.s.OauthServiceCreds.ClientSecret,
		Scopes:       e.s.OauthServiceCreds.Scopes,
		Endpoint:     endpoint,
		RedirectURL:  redirectUrl.String(),
	}

	for {
		state := generateRandomString()

		authUrl := oauthConf.AuthCodeURL(state)

		fmt.Println("Please go to this url and authorize the application:")
		fmt.Println(authUrl)
		fmt.Printf("Enter the code here> ")

		encodedAuthCode := term.readSimpleString()
		jsonAuthCode, err := base64.StdEncoding.DecodeString(encodedAuthCode)
		if err != nil {
			fmt.Println("Bad decode")
			continue
		}
		j := struct {
			Token string
			State string
		}{}
		json.Unmarshal(jsonAuthCode, &j)

		if j.State != state {
			fmt.Printf("Bad state. Expected %s, got %s\n", state, j.State)
			continue
		}

		token, err := oauthConf.Exchange(context.Background(), j.Token)
		if err == nil {
			e.a.OauthAccountCreds = token
			fmt.Println("Successfully authorized.")
			return true
		}
		fmt.Println(err)
		fmt.Println("Please try again.")
	}
}

func generateRandomString() string {
	b := make([]byte, 30)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func confirmRename(f actionFunc) actionFunc {
	return func(term *terminal) {
		if term.readBoolean("Editing a name will break existing connections.  Only do this if you're really ok with fixing everything!  Continue with rename? (yes/no)> ") {
			f(term)
		} else {
			fmt.Println("Cancelling name edit.")
		}
	}
}

func confirmNewClientCredentials(f actionFunc) actionFunc {
	return func(term *terminal) {
		if term.readBoolean("Creating new credentails will break existing connections.  Only do this if you're really ok with fixing everything!  Continue? (yes/no)> ") {
			f(term)
		} else {
			fmt.Println("Cancelling...")
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type terminal struct {
	scanner *bufio.Scanner
}

func newRealTerminal() *terminal {
	term := terminal{}
	term.scanner = bufio.NewScanner(os.Stdin)
	return &term
}

func (term *terminal) readName() string {
	for {
		fmt.Printf("Choose a name (only use lowercase letters, numbers, and dashes)> ")
		rawText := term.readSimpleString()
		if rawText == "" {
			fmt.Println("Name cannot be empty.")
			continue
		}
		match, _ := regexp.MatchString("^[-a-z0-9]+$", rawText)
		if !match {
			fmt.Println("That name contains invalid characters.")
			continue
		}
		return rawText
	}
}

func (term *terminal) readUrl(urlDescription string) string {
	for {
		fmt.Printf("Enter the %s> ", urlDescription)
		rawText := term.readSimpleString()
		tokenURL, err := url.ParseRequestURI(rawText)
		if err != nil {
			fmt.Println(rawText + " is not a valid URL (include https://)")
			continue
		}
		if tokenURL.Scheme != "https" {
			fmt.Println(rawText + " does not use https.")
			continue
		}

		return tokenURL.String()
	}
}

func (term *terminal) readSimpleString() string {
	term.scanner.Scan()
	return strings.TrimSpace(term.scanner.Text())
}

func (term *terminal) readStringList() []string {
	list := strings.Split(term.readSimpleString(), ",")
	for i := range list {
		list[i] = strings.TrimSpace(list[i])
	}
	return list
}

func (term *terminal) readBoolean(prompt string) bool {
	for {
		fmt.Printf(prompt)
		rawText := term.readSimpleString()
		if rawText == "yes" {
			return true
		}
		if rawText == "no" {
			return false
		}

		fmt.Println("'" + rawText + "' is not 'yes' or 'no'.  Please enter a valid option")
	}
}

func (term *terminal) readChoice(namer func(int) string, length int) int {
	for i := 0; i < length; i++ {
		fmt.Printf("[%d]: %s\n", i, namer(i))
	}
	for {
		fmt.Printf("Choose an option> ")
		rawText := term.readSimpleString()
		i, err := strconv.Atoi(rawText)
		if err == nil && i >= 0 && i < length {
			return i
		}
		fmt.Println(rawText + " is not a valid option. Enter only the number of the option.")
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type action struct {
	displayText string
	f           actionFunc
}

type actionFunc func(*terminal)

func newAction(displayText string, f actionFunc) *action {
	return &action{displayText, f}
}

func takeActionLoop(term *terminal, actions ...*action) {
	keepLoop := true
	back := newAction("Back", func(term *terminal) { keepLoop = false })

	actions = append([]*action{back}, actions...)

	for keepLoop {
		takeAction(term, actions...)
	}
}

func takeAction(term *terminal, actions ...*action) {
	i := term.readChoice(func(j int) string { return actions[j].displayText }, len(actions))
	actions[i].f(term)
}
