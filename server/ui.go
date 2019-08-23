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
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"net/url"

	uuid "github.com/gofrs/uuid"
	option "google.golang.org/api/option"
	plus "google.golang.org/api/plus/v1"

	"github.com/google/web-api-gateway/config"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	defaultSessionID     = "default"
	profileSessionKey    = "profile"
	oauthTokenSessionKey = "oauth_token"
	oauthFlowRedirectKey = "redirect"
)

var (
	baseTmpl        = parseTemplate("")
	listTmpl        = parseTemplate(*templatesFolder + "list.html")
	editServiceTmpl = parseTemplate(*templatesFolder + "editService.html")
	editAccountTmpl = parseTemplate(*templatesFolder + "editAccount.html")
	keyTmpl         = parseTemplate(*templatesFolder + "key.html")
)

var oauthConf *oauth2.Config = &oauth2.Config{
	ClientID:     "523939206127-3pr1qbrn0g78l6r9nu10l733q9obgn0t.apps.googleusercontent.com",
	ClientSecret: "zKY48Os4L8xKAuQoiBFqrLkW",
	Scopes:       []string{"email", "profile"},
	Endpoint:     google.Endpoint,
}

var cookieStore = createStore()

type data struct {
	Service *config.Service
	Account *config.Account
	Url     string
	State   string
}

type profile struct {
	ID, DisplayName, ImageURL string
	Emails                    []*plus.PersonEmails
}

func init() {
	gob.Register(&oauth2.Token{})
	gob.Register(&profile{})
}

func UIHandlers() *mux.Router {
	r := mux.NewRouter()

	r.Methods("GET").Path("/").Handler(appHandler(baseHandler))

	r.Methods("GET").Path("/portal/").Handler(appHandler(listHandler))
	r.Methods("GET").Path("/portal/addservice").Handler(appHandler(addServiceHandler))
	r.Methods("GET").Path("/portal/editservice/{service}").Handler(appHandler(editServiceHandler))
	r.Methods("GET").Path("/portal/removeservice/{service}").Handler(appHandler(removeServiceHandler))

	r.Methods("GET").Path("/portal/addaccount/{service}").Handler(appHandler(addAccountHandler))
	r.Methods("GET").Path("/portal/editaccount/{service}/{account}").Handler(appHandler(editAccountHandler))
	r.Methods("GET").Path("/portal/removeaccount/{service}/{account}").Handler(appHandler(removeAccountHandler))
	r.Methods("GET").Path("/portal/retrievekey/{service}/{account}").Handler(appHandler(retrieveKeyHandler))
	r.Methods("GET").Path("/portal/reauthorizeaccount/{service}/{account}").Handler(appHandler(reauthorizeAccountHandler))

	r.Methods("POST").Path("/portal/saveservice").Handler(appHandler(saveServiceHandler))
	r.Methods("POST").Path("/portal/saveaccount").Handler(appHandler(saveAccountHandler))

	r.Methods("GET").Path("/login").Handler(appHandler(loginHandler))
	r.Methods("GET").Path("/auth").Handler(appHandler(oauthCallbackHandler))
	r.Methods("POST").Path("/logout").Handler(appHandler(logoutHandler))

	return r
}

// loginHandler initiates an OAuth flow to the Google+ API
func loginHandler(w http.ResponseWriter, r *http.Request) *appError {
	sessionID := uuid.Must(uuid.NewV4()).String()

	oauthFlowSession, err := cookieStore.New(r, sessionID)
	if err != nil {
		return appErrorf(err, "could not create oauth session: %v", err)
	}
	oauthFlowSession.Options.MaxAge = 10 * 60 // 10 minutes

	// redirectURL, err := validateRedirectURL(r.FormValue("redirect"))
	// if err != nil {
	//  return appErrorf(err, "invalid redirect URL: %v", err)
	// }
	// oauthFlowSession.Values[oauthFlowRedirectKey] = redirectURL

	if err := oauthFlowSession.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
	}

	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}
	redirectUrl, err := url.Parse(c.Url)
	if err != nil {
		return appErrorf(err, "could not parse URL: %v", err)
	}

	redirectUrl.Path = "/auth"
	oauthConf.RedirectURL = redirectUrl.String()
	url := oauthConf.AuthCodeURL(sessionID, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) *appError {
	// Validate state parameter using session
	_, err := cookieStore.Get(r, r.FormValue("state"))
	if err != nil {
		return appErrorf(err, "invalid state parameter. try logging in again.")
	}

	// redirectURL, ok := oauthFlowSession.Values[oauthFlowRedirectKey].(string)
	// // Validate this callback request came from the app.
	// if !ok {
	//  return appErrorf(err, "invalid state parameter. try logging in again.")
	// }

	///////////////////////////////
	ctx := context.Background()
	code := r.FormValue("code")
	tok, err := oauthConf.Exchange(ctx, code)
	if err != nil {
		return appErrorf(err, "could not get auth token: %v", err)
	}
	session, err := cookieStore.New(r, defaultSessionID)
	if err != nil {
		// TODO: point 8
		appErrorf(err, "could not get default session: %v", err)
		// return appErrorf(err, "could not get default session: %v", err)
	}
	plusService, err := plus.NewService(ctx, option.WithTokenSource(oauthConf.TokenSource(ctx, tok)))
	if err != nil {
		return appErrorf(err, "could not get plus service: %v", err)
	}
	person, err := plusService.People.Get("me").Do()
	if err != nil {
		return appErrorf(err, "could not fetch Google profiles: %v", err)
	}
	profile := stripProfile(person)

	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}

	// emmm [0]?
	log.Println(profile.Emails)
	emailValue := profile.Emails[0].Value
	if c.Users[emailValue] {
		session.Values[oauthTokenSessionKey] = tok
		session.Values[profileSessionKey] = profile
		if err := session.Save(r, w); err != nil {
			return appErrorf(err, "could not save session: %v", err)
		}
	}

	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) *appError {
	session, err := cookieStore.New(r, defaultSessionID)
	if err != nil {
		return appErrorf(err, "could not get default session: %v", err)
	}
	session.Options.MaxAge = -1 // Clear session.
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
	return nil
}

func baseHandler(w http.ResponseWriter, r *http.Request) *appError {
	return baseTmpl.Execute(w, r, nil)
}

func listHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}
	return listTmpl.Execute(w, r, *c)
}

func editServiceHandler(w http.ResponseWriter, r *http.Request) *appError {
	return editHandler(w, r, editServiceTmpl)
}

func editAccountHandler(w http.ResponseWriter, r *http.Request) *appError {
	return editHandler(w, r, editAccountTmpl)
}

func addServiceHandler(w http.ResponseWriter, r *http.Request) *appError {
	return editServiceTmpl.Execute(w, r, nil)
}

func addAccountHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}
	serviceStr := mux.Vars(r)["service"]
	_, service, err := serviceFromRequest(serviceStr, c)
	if err != nil {
		return appErrorf(err, "could not find service: %v", err)
	}
	oauthConf, err := config.GenerateOauthConfig(c.Url, service)
	if err != nil {
		return appErrorf(err, "could not get Oauth config: %v", err)
	}
	authUrl, state, err := config.GenerateAuthUrl(oauthConf)
	if err != nil {
		return appErrorf(err, "could not generate auth URL: %v", err)
	}

	return editAccountTmpl.Execute(w, r, data{service, nil, authUrl, state})
}

func saveServiceHandler(w http.ResponseWriter, r *http.Request) *appError {
	name := r.FormValue("PreviousServiceName")
	u, err := config.NewServiceUpdater(name)
	if err != nil {
		return appErrorf(err, "could not get service updater: %v", err)
	}
	// the warning is in title
	if err := u.Name(r.FormValue("ServiceName")); err != nil {
		return appErrorf(err, "could not update service name: %v", err)
	}

	// validations?
	u.ClientID(r.FormValue("ClientID"))
	u.ClientSecret(r.FormValue("ClientSecret"))
	u.AuthURL(r.FormValue("AuthURL"))
	u.TokenURL(r.FormValue("TokenURL"))
	u.Scopes(r.FormValue("Scopes"))

	if err := u.Commit(); err != nil {
		return appErrorf(err, "could not save changes: %v", err)
	}
	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
}

func saveAccountHandler(w http.ResponseWriter, r *http.Request) *appError {
	sName := r.FormValue("ServiceName")
	previousAccount := r.FormValue("PreviousAccountName")

	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}
	idx, _, err := serviceFromRequest(sName, c)
	if err != nil {
		return appErrorf(err, "could not find service: %v", err)
	}
	u, err := config.NewAccountUpdater(previousAccount, idx)
	if err != nil {
		return appErrorf(err, "could not get account updater: %v", err)
	}
	if err := u.Name(r.FormValue("AccountName")); err != nil {
		return appErrorf(err, "could not update account name: %v", err)
	}
	u.ServiceURL(r.FormValue("ServiceURL"))

	state := r.FormValue("State")
	code := r.FormValue("Code")
	if code != "" {
		// how should err being used here to pop up msg(?)
		decode, _ := config.VerifyState(code, state)
		if decode == "" {
			if previousAccount == "" {
				http.Redirect(w, r, fmt.Sprintf("/portal/addaccount/%s", sName), http.StatusFound)
				return nil
			}
			http.Redirect(w, r,
				fmt.Sprintf("/portal/reauthorizeaccount/%s/%s", sName, previousAccount),
				http.StatusFound)
			return nil
		}
		// switch to this
		// if err := u.OauthCreds(decode); err != nil {
		//  return appErrorf(err, "could not update Oauth credentials: %v", err)
		// }
		u.OauthCreds(decode)
	}
	if r.FormValue("GenerateNewCreds") == "on" || previousAccount == "" {
		if err := u.ClientCreds(); err != nil {
			return appErrorf(err, "could not generate client credentails: %v", err)
		}
	}

	if err := u.Commit(); err != nil {
		return appErrorf(err, "could not save changes: %v", err)
	}
	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
}

func removeServiceHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}

	serviceStr := mux.Vars(r)["service"]
	i, _, err := serviceFromRequest(serviceStr, c)
	if err != nil {
		return appErrorf(err, "could not find service: %v", err)
	}

	if err := config.RemoveService(i); err != nil {
		return appErrorf(err, "could not delete service: %v", err)
	}

	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
}

func removeAccountHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}

	serviceStr := mux.Vars(r)["service"]
	sIdx, service, err := serviceFromRequest(serviceStr, c)
	if err != nil {
		return appErrorf(err, "could not find service: %v", err)
	}

	accountStr := mux.Vars(r)["account"]
	i, _, err := accountFromRequest(accountStr, service)
	if err != nil {
		return appErrorf(err, "could not find account: %v", err)
	}

	if config.RemoveAccount(i, sIdx) != nil {
		return appErrorf(err, "could not delete account: %v", err)
	}
	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
}

func editHandler(w http.ResponseWriter, r *http.Request, tmpl *appTemplate) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}

	serviceStr := mux.Vars(r)["service"]
	_, service, err := serviceFromRequest(serviceStr, c)
	if err != nil {
		return appErrorf(err, "could not find service: %v", err)
	}
	if tmpl == editServiceTmpl {
		return tmpl.Execute(w, r, service)
	} else {
		accountStr := mux.Vars(r)["account"]
		_, account, err := accountFromRequest(accountStr, service)
		if err != nil {
			return appErrorf(err, "could not find account: %v", err)
		}
		return tmpl.Execute(w, r, data{service, account, "", ""})
	}
}

func retrieveKeyHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}

	serviceStr := mux.Vars(r)["service"]
	_, service, err := serviceFromRequest(serviceStr, c)
	if err != nil {
		return appErrorf(err, "could not find service: %v", err)
	}
	accountStr := mux.Vars(r)["account"]
	_, account, err := accountFromRequest(accountStr, service)
	if err != nil {
		return appErrorf(err, "could not find account: %v", err)
	}
	key, err := config.GenerateAccountKey(c, service, account)
	if err != nil {
		return appErrorf(err, "could not create account key: %v", err)
	}
	return keyTmpl.Execute(w, r, key)
}

func reauthorizeAccountHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}

	serviceStr := mux.Vars(r)["service"]
	_, service, err := serviceFromRequest(serviceStr, c)
	if err != nil {
		return appErrorf(err, "could not find service: %v", err)
	}
	accountStr := mux.Vars(r)["account"]
	_, account, err := accountFromRequest(accountStr, service)
	if err != nil {
		return appErrorf(err, "could not find account: %v", err)
	}
	oauthConf, err := config.GenerateOauthConfig(c.Url, service)
	if err != nil {
		return appErrorf(err, "could not get Oauth config: %v", err)
	}
	authUrl, state, err := config.GenerateAuthUrl(oauthConf)
	if err != nil {
		return appErrorf(err, "could not generate auth URL: %v", err)
	}

	return editAccountTmpl.Execute(w, r, data{service, account, authUrl, state})
}

func serviceFromRequest(serviceStr string, c *config.Config) (int, *config.Service, error) {
	for i, s := range c.Services {
		if serviceStr == s.ServiceName {
			return i, s, nil
		}
	}
	return -1, nil, fmt.Errorf("No such service: %s", serviceStr)
}

func accountFromRequest(accountStr string, s *config.Service) (int, *config.Account, error) {
	for i, a := range s.Accounts {
		if accountStr == a.AccountName {
			return i, a, nil
		}
	}
	return -1, nil, fmt.Errorf("No such account: %s", accountStr)
}

func stripProfile(p *plus.Person) *profile {
	return &profile{
		Emails:      p.Emails,
		DisplayName: p.DisplayName,
		ImageURL:    p.Image.Url,
	}
}

func createStore() *sessions.CookieStore {
	store := sessions.NewCookieStore(securecookie.GenerateRandomKey(32))
	store.Options = &sessions.Options{
		Secure:   true,
		MaxAge:   86400 * 7, // TODO: change to another duration?
		HttpOnly: true,
	}
	return store
}

// profileFromSession retreives the Google+ profile from the default session.
// Returns nil if the profile cannot be retreived (e.g. user is logged out).
func profileFromSession(r *http.Request) *profile {
	session, err := cookieStore.Get(r, defaultSessionID)
	if err != nil {
		return nil
	}
	tok, ok := session.Values[oauthTokenSessionKey].(*oauth2.Token)
	if !ok || !tok.Valid() {
		return nil
	}
	profile, ok := session.Values[profileSessionKey].(*profile)
	if !ok {
		return nil
	}
	return profile
}

type appHandler func(http.ResponseWriter, *http.Request) *appError

type appError struct {
	Error   error
	Message string
	Code    int
}

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil { // e is *appError, not os.Error.
		log.Printf("Handler error: status code: %d, message: %s, underlying err: %#v",
			e.Code, e.Message, e.Error)

		http.Error(w, e.Message, e.Code)
	}
}

func appErrorf(err error, format string, v ...interface{}) *appError {
	return &appError{
		Error:   err,
		Message: fmt.Sprintf(format, v...),
		Code:    500,
	}
}
