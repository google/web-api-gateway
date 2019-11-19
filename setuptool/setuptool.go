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

// The command line tool for setting up services and accounts.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/web-api-gateway/config"
)

func main() {
	flag.Parse()
	fmt.Printf("Welcome to the Web Api Gateway Config Tool.\n\n")

	c, _, err := config.ReadWriteConfig()
	if err != nil {
		fmt.Printf("Unable to load config file %v\n", err)
	}

	term := newRealTerm()

	if c.Url == "" {
		editUrl(term)
	}

	takeActionLoop(term, backIsExit,
		newAction("Retrieve Account Key", retrieveAccountKey),
		newAction("Edit Web Api Gateway Url", editUrl),
		newAction("Add Service", addService),
		newAction("Edit Service", editService),
		newAction("Delete Service", removeService),
		newAction("Add Account", addAccount),
		newAction("Edit Account", editAccount),
		newAction("Delete Account", removeAccount),
		newAction("Add authorized UI users (email address)", addUser),
		newAction("Delete authorized UI users (email address)", removeUser),
	)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type commiter interface {
	Commit() (interface{}, error)
}

func commit(t *term, c commiter) {
	fmt.Println("Saving...")

	for {
		_, err := c.Commit()
		if err == nil {
			fmt.Println("Save successful!")
			fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			fmt.Println("Remember to restart the server.")
			fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			return
		}
		fmt.Printf("There was an error saving the config file: %v\n", err)
		tryAgain := t.readBoolean("Do you want to try again? (no to discard unsaved changes.)")
		if !tryAgain {
			return
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func editUrl(t *term) {
	userInput(t, "Enter the Web Api Gateway Url> ", config.SetEndpointUrl)
}

func ServiceName(u *config.ServiceUpdater, t *term) {
	userInput(t, "Choose a name (only use lowercase letters, numbers, and dashes)> ", u.Name)
}

func ServiceClientID(u *config.ServiceUpdater, t *term) {
	userInput(t, "Enter the Oauth Client ID> ", u.ClientID)
}

func ServiceClientSecret(u *config.ServiceUpdater, t *term) {
	userInput(t, "Enter the Oauth Client Secret> ", u.ClientSecret)
}

func ServiceAuthURL(u *config.ServiceUpdater, t *term) {
	userInput(t, "Enter the Oauth Auth URL> ", u.AuthURL)
}

func ServiceTokenURL(u *config.ServiceUpdater, t *term) {
	userInput(t, "Enter the Oauth Token URL> ", u.TokenURL)
}

func ServiceScopes(u *config.ServiceUpdater, t *term) {
	userInput(t, "Enter the Oauth scopes> ", u.Scopes)
}

func AccountName(u *config.AccountUpdater, t *term) {
	userInput(t, "Choose a name (only use lowercase letters, numbers, and dashes)> ", u.Name)
}

func AccountServiceURL(u *config.AccountUpdater, t *term) {
	userInput(t, "Enter the Service URL> ", u.ServiceURL)
}

func AccountOauthCreds(u *config.AccountUpdater, t *term) bool {
	oauthConf, err := config.GenerateOauthConfig(u.C.Url, u.C.Services[u.S])
	if err != nil {
		return false
	}
	for {
		authUrl, state, err := config.GenerateAuthUrl(oauthConf)
		if err != nil {
			fmt.Println(err)
			return false
		}
		fmt.Println("Please go to this url and authorize the application:")
		fmt.Println(authUrl)
		fmt.Printf("Enter the code here> ")
		encodedAuthCode := t.readSimpleString()
		decodedToken, err := config.VerifyState(encodedAuthCode, state)

		if err != nil {
			fmt.Println(err)
			continue
		}
		if err = u.OauthCreds(decodedToken); err == nil {
			return true
		}
		fmt.Println(err)
		fmt.Println("\nPlease try again.")
	}
}

func AccountClientCreds(u *config.AccountUpdater, t *term) {
	if err := u.ClientCreds(); err != nil {
		fmt.Println(err)
	}
}

func addService(t *term) {
	u, err := config.NewServiceUpdater("")
	if err != nil {
		fmt.Println(err)
		return
	}

	ServiceName(u, t)
	ServiceClientID(u, t)
	ServiceClientSecret(u, t)
	ServiceAuthURL(u, t)
	ServiceTokenURL(u, t)
	ServiceScopes(u, t)

	commit(t, u)
}

func serviceCurry(f func(*config.ServiceUpdater, *term), u *config.ServiceUpdater) func(*term) {
	return func(t *term) {
		f(u, t)
	}
}

func editService(t *term) {
	_, name := chooseService(t)
	if name == "" {
		return
	}
	u, err := config.NewServiceUpdater(name)
	if err != nil {
		fmt.Println(err)
		return
	}

	takeActionLoop(t, backIsBack,
		newAction("Edit name", confirmRename(serviceCurry(ServiceName, u))),
		newAction("Edit Client Id", serviceCurry(ServiceClientID, u)),
		newAction("Edit Client Secret", serviceCurry(ServiceClientSecret, u)),
		newAction("Edit Auth Url", serviceCurry(ServiceAuthURL, u)),
		newAction("Edit Token Url", serviceCurry(ServiceTokenURL, u)),
		newAction("Edit Scopes", serviceCurry(ServiceScopes, u)))

	commit(t, u)
}

func removeService(t *term) {
	idx, name := chooseService(t)
	if idx == -1 {
		return
	}
	if config.RemoveService(idx) != nil {
		fmt.Println("Error deleting service: " + name)
		return
	}
}

func addAccount(t *term) {
	idx, _ := chooseService(t)
	if idx == -1 {
		return
	}
	u, err := config.NewAccountUpdater("", idx)
	if err != nil {
		fmt.Println(err)
		return
	}

	AccountName(u, t)
	AccountServiceURL(u, t)
	AccountClientCreds(u, t)

	if !AccountOauthCreds(u, t) {
		fmt.Println("Could not add account")
		return
	}
	commit(t, u)
}

func accountCurry(f func(*config.AccountUpdater, *term), u *config.AccountUpdater) func(*term) {
	return func(t *term) {
		f(u, t)
	}
}

func accountCurry2(f func(*config.AccountUpdater, *term) bool, u *config.AccountUpdater) func(*term) {
	return func(t *term) {
		f(u, t)
	}
}

func editAccount(t *term) {
	idx, _ := chooseService(t)
	if idx == -1 {
		return
	}
	_, name := chooseAccount(t, idx)
	if name == "" {
		return
	}
	u, err := config.NewAccountUpdater(name, idx)
	if err != nil {
		fmt.Println(err)
		return
	}

	takeActionLoop(t, backIsBack,
		newAction("Edit name", confirmRename(accountCurry(AccountName, u))),
		newAction("Edit service Url", accountCurry(AccountServiceURL, u)),
		newAction("Generate New Client Credentials", confirmNewClientCredentials(accountCurry(AccountClientCreds, u))),
		newAction("Reauthorzie account", accountCurry2(AccountOauthCreds, u)))

	commit(t, u)
}

func removeAccount(t *term) {
	s, _ := chooseService(t)
	if s == -1 {
		return
	}
	a, name := chooseAccount(t, s)
	if a == -1 {
		return
	}
	if config.RemoveAccount(s, a) != nil {
		fmt.Println("Error deleting account: " + name)
		return
	}
}

func retrieveAccountKey(t *term) {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println("Unable to read config", err)
		return
	}

	type accountSpecific struct {
		s *config.Service
		a *config.Account
	}

	allAccounts := make([]accountSpecific, 0)

	for _, s := range c.Services {
		for _, a := range s.Accounts {
			allAccounts = append(allAccounts, accountSpecific{s, a})
		}
	}

	if len(allAccounts) == 0 {
		fmt.Println("You must create accounts first!")
		return
	}

	fmt.Println("Select which account:")
	namer := func(i int) string {
		return allAccounts[i].s.ServiceName + "/" + allAccounts[i].a.AccountName
	}
	i := t.readChoice(namer, len(allAccounts))

	key, err := config.GenerateAccountKey(c, allAccounts[i].s, allAccounts[i].a)
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
}

func addUser(t *term) {
	userInput(t, "Enter the users' emails> ", config.AddUser)
	fmt.Println("User added.\n")
}

func removeUser(t *term) {
	userInput(t, "Enter the users' email> ", config.RemoveUser)
	fmt.Println("User removed.\n")
}

func chooseService(t *term) (int, string) {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println("Unable to read config", err)
		return -1, ""
	}

	if len(c.Services) == 0 {
		fmt.Println("There are no services.")
		return -1, ""
	}

	fmt.Println("Services:")

	var names []string

	for _, s := range c.Services {
		names = append(names, s.ServiceName)
	}

	namer := func(i int) string { return names[i] }
	idx := t.readChoice(namer, len(c.Services))
	return idx, names[idx]
}

func chooseAccount(t *term, s int) (int, string) {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println("Unable to read config", err)
		return -1, ""
	}

	if len(c.Services[s].Accounts) == 0 {
		fmt.Println("There are no accounts.\n")
		return -1, ""
	}

	fmt.Println("Accounts:")

	var names []string

	for _, a := range c.Services[s].Accounts {
		names = append(names, a.AccountName)
	}

	namer := func(i int) string { return names[i] }
	idx := t.readChoice(namer, len(c.Services[s].Accounts))
	return idx, names[idx]
}

func userInput(t *term, prompt string, handler func(string) error) {
	for {
		fmt.Println(prompt)
		i := t.readSimpleString()
		err := handler(i)
		if err != nil {
			fmt.Println("Invalid value, ", err.Error())
			continue
		}
		break
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

func confirmRename(f actionFunc) actionFunc {
	return func(t *term) {
		if t.readBoolean("Editing a name will break existing connections.  Only do this if you're really ok with fixing everything!  Continue with rename? (yes/no)> ") {
			f(t)
		} else {
			fmt.Println("Cancelling name edit.")
		}
	}
}

func confirmNewClientCredentials(f actionFunc) actionFunc {
	return func(t *term) {
		if t.readBoolean("Creating new credentails will break existing connections.  Only do this if you're really ok with fixing everything!  Continue? (yes/no)> ") {
			f(t)
		} else {
			fmt.Println("Cancelling...")
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type term struct {
	scanner *bufio.Scanner
}

func newRealTerm() *term {
	term := term{}
	term.scanner = bufio.NewScanner(os.Stdin)
	return &term
}

func (t *term) readSimpleString() string {
	t.scanner.Scan()
	return strings.TrimSpace(t.scanner.Text())
}

func (t *term) readBoolean(prompt string) bool {
	for {
		fmt.Printf(prompt)
		rawText := t.readSimpleString()
		if rawText == "yes" {
			return true
		}
		if rawText == "no" {
			return false
		}

		fmt.Println("'" + rawText + "' is not 'yes' or 'no'.  Please enter a valid option")
	}
}

func (t *term) readChoice(namer func(int) string, length int) int {
	for i := 0; i < length; i++ {
		fmt.Printf("[%d]: %s\n", i, namer(i))
	}
	for {
		fmt.Printf("Choose an option> ")
		rawText := t.readSimpleString()
		i, err := strconv.Atoi(rawText)
		if err == nil && i >= 0 && i < length {
			return i
		}
		fmt.Println(rawText + " is not a valid option. Enter only the number of the option.")
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type backIs string

const (
	backIsBack = backIs("Back")
	backIsExit = backIs("Exit")
)

type action struct {
	displayText string
	f           actionFunc
}

type actionFunc func(*term)

func newAction(displayText string, f actionFunc) *action {
	return &action{displayText, f}
}

func takeActionLoop(t *term, backName backIs, actions ...*action) {
	keepLoop := true

	back := newAction(string(backName), func(t *term) { keepLoop = false })

	actions = append([]*action{back}, actions...)

	for keepLoop {
		takeAction(t, actions...)
	}
}

func takeAction(t *term, actions ...*action) {
	i := t.readChoice(func(j int) string { return actions[j].displayText }, len(actions))
	actions[i].f(t)
}
