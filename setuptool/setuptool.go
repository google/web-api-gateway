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
	"os"
	"strconv"
	"strings"

	"github.com/google/web-api-gateway/config"
)

func main() {
	flag.Parse()
	fmt.Printf("Welcome to the Web Api Gateway Config Tool.\n\n")

	term := newRealTerm()

	takeActionLoop(term, backIsExit,
		newAction("Add Service", addService),
		newAction("Edit Service", editService),
	)
	// newAction("Retrieve Account Key", e.retrieveAccountKey),
	// newAction("Edit Web Api Gateway Url", e.editUrl),
	// newAction("Add service", e.addService),
	// newAction("Edit service (including adding new accounts to an existing service)", e.editService),
	// newAction("Delete service", e.removeService))
	// add account
	// edit account
	// remove account
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

type commiter interface {
	Commit() error
}

func commit(t *term, c commiter) {
	fmt.Println("Saving...")

	for {
		err := c.Commit()
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

type serviceEdit struct {
	prompt string
	f      func(*config.ServiceUpdater, string) error
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
	name := chooseService(t)
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

func chooseService(t *term) string {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println("Unable to read config", err)
		return ""
	}

	if len(c.Services) == 0 {
		fmt.Println("There are no services.")
		return ""
	}

	fmt.Println("Services:")

	var names []string

	for _, s := range c.Services {
		names = append(names, s.ServiceName)
	}

	namer := func(i int) string { return names[i] }
	return names[t.readChoice(namer, len(c.Services))]
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
