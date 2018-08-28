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
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"web-api-gateway/config"
	// "golang.org/x/oauth2"
)

// BEFORE RELEASE TODO: Make sure that it's not possible to give names to services / accounts
// that conflict with other accounts at that level.

func main() {
	flag.Parse()
	fmt.Printf("Welcome to the Web Api Gateway Config Tool.\n\n")

	con := newRealContext()

	c, save, err := config.ReadWriteConfig()
	if err != nil {
		fmt.Printf("Unable to load config file: %v/n", err)
		os.Exit(1)
	}

	e := &configEditor{c}
	e.edit(con)

	fmt.Println("Saving...")
	for {
		err = save()
		if err == nil {
			return
		}
		fmt.Printf("There was an error saving the config file: %v/n", err)
		tryAgain := con.readBoolean("Do you want to try again? (no to lose all changes and exit.)")
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

func (e *configEditor) edit(c *context) {
	takeActionLoop(c,
		newAction("Add service", e.addService),
		newAction("Edit service (including adding new accounts to an existing service)", e.editService),
		newAction("Delete service", e.removeService))
}

func (e *configEditor) addService(c *context) {
	s := newService(c)
	e.c.Services = append(e.c.Services, s)
}

func (e *configEditor) editService(c *context) {
	fmt.Println("Services:")
	var actions []*action
	for i := range e.c.Services {
		// Avoid using the last service from the loop in the lambda.
		service := e.c.Services[i]
		action := newAction(service.ServiceName, editService(service))
		actions = append(actions, action)
	}
	takeAction(c, actions...)
}

func (e *configEditor) removeService(c *context) {
	fmt.Println("lol, not done yet")
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type serviceEditor struct {
	s *config.Service
}

func newService(c *context) *config.Service {
	s := &config.Service{}
	e := &serviceEditor{s}

	e.setName(c)
	e.s.OauthServiceCreds = newOauthServiceCreds(c)
	e.edit(c) // Give user chance to add accounts right away

	return s
}

func editService(s *config.Service) actionFunc {
	return (&serviceEditor{s}).edit
}

func (e *serviceEditor) edit(c *context) {
	takeActionLoop(c,
		newAction("Edit name", confirmRename(e.setName)),
		newAction("Edit OAuth credentials", editOauthServiceCreds(e.s.OauthServiceCreds)),
		newAction("Add new account", e.addAccount),
		newAction("Edit account", e.editAccount),
		newAction("Remove account", e.removeAccount))
}

func (e *serviceEditor) setName(c *context) {
	e.s.ServiceName = c.readName()
}

func (e *serviceEditor) addAccount(c *context) {
	a := newAccount(c)
	e.s.Accounts = append(e.s.Accounts, a)
}

func (e *serviceEditor) editAccount(c *context) {
	fmt.Println("lol, not done yet")
}

func (e *serviceEditor) removeAccount(c *context) {
	fmt.Println("lol, not done yet")
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type oauthServiceCredsEditor struct {
	o *config.OauthServiceCreds
}

func newOauthServiceCreds(c *context) *config.OauthServiceCreds {
	o := &config.OauthServiceCreds{}
	e := &oauthServiceCredsEditor{o}

	e.setClientId(c)
	e.setClientSecret(c)
	e.setAuthURL(c)
	e.setTokenURL(c)
	// Need to set scopes variable to work for all services.

	return o
}

func editOauthServiceCreds(o *config.OauthServiceCreds) actionFunc {
	return (&oauthServiceCredsEditor{o}).edit
}

func (e *oauthServiceCredsEditor) edit(c *context) {
	fmt.Println("lol, not done yet")
}

func (e *oauthServiceCredsEditor) setClientId(c *context) {
	fmt.Printf("Enter the client id> ")
	e.o.ClientID = c.readSimpleText()
}

func (e *oauthServiceCredsEditor) setClientSecret(c *context) {
	fmt.Printf("Enter the client secret> ")
	e.o.ClientSecret = c.readSimpleText()
}

func (e *oauthServiceCredsEditor) setAuthURL(c *context) {
	e.o.AuthURL = c.readUrl("Auth URL")
}

func (e *oauthServiceCredsEditor) setTokenURL(c *context) {
	e.o.TokenURL = c.readUrl("Token URL")
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type accountEditor struct {
	a *config.Account
}

func newAccount(c *context) *config.Account {
	a := &config.Account{}
	e := &accountEditor{a}

	e.setName(c)
	e.a.OauthAccountCreds = newOauthAccountCreds(c)
	e.a.ClientCreds = newClientCreds(c)

	return a
}

func (e *accountEditor) setName(c *context) {
	e.a.AccountName = c.readName()
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func newOauthAccountCreds(c *context) *config.OauthAccountCreds {
	o := &config.OauthAccountCreds{}
	o.ServiceURL = "SERVICE_URL"
	o.RefreshToken = "REFRESH_TOKEN"
	return o
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func newClientCreds(c *context) *config.ClientCreds {
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func confirmRename(f actionFunc) actionFunc {
	return func(c *context) {
		if c.readBoolean("Editing a name will break existing connections.  Only do this if you're really ok with fixing everything!  Continue with rename? (yes/no)> ") {
			f(c)
		} else {
			fmt.Println("Cancelling name edit.")
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type context struct {
	scanner *bufio.Scanner
}

func newRealContext() *context {
	c := context{}
	c.scanner = bufio.NewScanner(os.Stdin)
	return &c
}

func (c *context) readName() string {
	for {
		fmt.Printf("Choose a name (only use lowercase letters, numbers, and dashes)> ")
		rawText := c.readSimpleText()
		match, _ := regexp.MatchString("^[-a-z0-9]+$", rawText)
		if match {
			return rawText
		}
		fmt.Println("That name contains invalid characters.")
	}
}

func (c *context) readUrl(urlDescription string) string {
	for {
		fmt.Printf("Enter the %s> ", urlDescription)
		rawText := c.readSimpleText()
		tokenURL, err := url.ParseRequestURI(rawText)
		if err == nil {
			return tokenURL.String()
		}
		fmt.Println(rawText + " is not a valid token URL")
	}
}

func (c *context) readSimpleText() string {
	c.scanner.Scan()
	return strings.TrimSpace(c.scanner.Text())
}

func (c *context) readBoolean(prompt string) bool {
	for {
		fmt.Printf(prompt)
		rawText := c.readSimpleText()
		if rawText == "yes" {
			return true
		}
		if rawText == "no" {
			return false
		}

		fmt.Println("'" + rawText + "' is not 'yes' or 'no'.  Please enter a valid option")
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type action struct {
	displayText string
	f           actionFunc
}

type actionFunc func(c *context)

func newAction(displayText string, f actionFunc) *action {
	return &action{displayText, f}
}

func takeActionLoop(c *context, actions ...*action) {
	keepLoop := true
	back := newAction("Back", func(c *context) { keepLoop = false })

	actions = append([]*action{back}, actions...)

	for keepLoop {
		takeAction(c, actions...)
	}
}

func takeAction(c *context, actions ...*action) {
	for idx, a := range actions {
		fmt.Printf("[%d]: %s\n", idx, a.displayText)
	}
	for {
		fmt.Printf("Choose an option> ")
		rawText := c.readSimpleText()
		index, err := strconv.Atoi(rawText)
		if err == nil && index >= 0 && index < len(actions) {
			actions[index].f(c)
			break
		}
		fmt.Println(rawText + " is not a valid option. Enter only the number of the option.")
	}
}
