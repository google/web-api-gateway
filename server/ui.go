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

package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

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
	stateSessionKey      = "state"
	oauthFlowRedirectKey = "redirect"
)

var (
	listTmpl        = parseTemplate(*templatesFolder + "list.html")
	editServiceTmpl = parseTemplate(*templatesFolder + "editService.html")
	editAccountTmpl = parseTemplate(*templatesFolder + "editAccount.html")
	keyTmpl         = parseTemplate(*templatesFolder + "key.html")
	userTmpl        = parseTemplate(*templatesFolder + "user.html")
	uploadTmpl      = parseTemplate(*templatesFolder + "upload.html")
)

var oauthConf *oauth2.Config = &oauth2.Config{
	ClientID:     "523939206127-3pr1qbrn0g78l6r9nu10l733q9obgn0t.apps.googleusercontent.com",
	ClientSecret: "zKY48Os4L8xKAuQoiBFqrLkW",
	Scopes:       []string{"email", "profile"},
	Endpoint:     google.Endpoint,
}

var cookieStore = createStore()

var engineMap = make(map[string]*config.Engine)

type data struct {
	Service  *config.Service
	Account  *config.Account
	Url      string
	Template *config.Template
	Domains  []*config.Domain
}

type profile struct {
	ID, DisplayName, ImageURL string
	Emails                    []*plus.PersonEmails
}

func init() {
	gob.Register(&oauth2.Token{})
	gob.Register(&profile{})

	createMapping()
}

func UIHandlers() *mux.Router {
	r := mux.NewRouter()

	r.Handle("/portal", http.RedirectHandler("/portal/", http.StatusFound))

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

	r.Methods("GET").Path("/portal/login").Handler(appHandler(loginHandler))
	r.Methods("GET").Path("/portal/auth").Handler(appHandler(oauthCallbackHandler))
	r.Methods("POST").Path("/portal/logout").Handler(appHandler(logoutHandler))

	r.Methods("GET").Path("/portal/users").Handler(appHandler(listUserHandler))
	r.Methods("POST").Path("/portal/adduser").Handler(appHandler(addUserHandler))
	r.Methods("GET").Path("/portal/removeuser/{user}").Handler(appHandler(removeUserHandler))

	r.Methods("GET").Path("/portal/upload").Handler(appHandler(uploadHandler))
	r.Methods("POST").Path("/portal/mapping").Handler(appHandler(mappingHandler))

	r.PathPrefix("/portal/static/").Handler(http.StripPrefix("/portal/static/",
		http.FileServer(http.Dir("/go/src/github.com/google/web-api-gateway/server/static"))))

	return r
}

func loginHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}
	redirectUrl, err := url.Parse(c.Url)
	if err != nil {
		return appErrorf(err, "could not parse URL: %v", err)
	}

	redirectUrl.Path = "/portal/auth"
	oauthConf.RedirectURL = redirectUrl.String()

	sessionID := uuid.Must(uuid.NewV4()).String()
	oauthFlowSession, err := cookieStore.New(r, sessionID)
	if err != nil {
		return appErrorf(err, "could not create oauth session: %v", err)
	}
	oauthFlowSession.Options.MaxAge = 10 * 60 // 10 minutes
	oauthFlowSession.Values[oauthFlowRedirectKey] = redirectUrl.Path
	if err := oauthFlowSession.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
	}

	url := oauthConf.AuthCodeURL(sessionID, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) *appError {
	oauthFlowSession, err := cookieStore.Get(r, r.FormValue("state"))
	if err != nil {
		return appErrorf(err, "invalid state parameter. try logging in again.")
	}

	// ?
	redirectURL, ok := oauthFlowSession.Values[oauthFlowRedirectKey].(string)
	if !ok || strings.Compare(r.URL.Path, redirectURL) != 0 {
		return &appError{Message: "The callback is suspicious."}
	}

	ctx := context.Background()
	code := r.FormValue("code")
	tok, err := oauthConf.Exchange(ctx, code)
	if err != nil {
		return appErrorf(err, "could not get auth token: %v", err)
	}
	// if browser saved an old session with name "default", the err here will
	// not be nil, but this is ok, so no need to check on err
	session, _ := cookieStore.New(r, defaultSessionID)
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

	emailValue := profile.Emails[0].Value
	if c.Users[emailValue] {
		session.Values[oauthTokenSessionKey] = tok
		session.Values[profileSessionKey] = profile
		if err := session.Save(r, w); err != nil {
			return appErrorf(err, "could not save session: %v", err)
		}
	} else {
		session.AddFlash("Sorry you are not authorized, please contact IT department.")
		if err := session.Save(r, w); err != nil {
			return appErrorf(err, "could not save session: %v", err)
		}
	}

	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) *appError {
	session, err := cookieStore.Get(r, defaultSessionID)
	if err != nil {
		return appErrorf(err, "could not get default session: %v", err)
	}
	session.Options.MaxAge = -1 // Clear session.
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
	}
	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
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
	tmp, err := config.ReadTemplate()
	if err != nil {
		return appErrorf(err, "could not read template: %v", err)
	}

	if tmp == nil || len(tmp.Engines) == 0 {
		http.Redirect(w, r, "/portal/upload", http.StatusFound)
	}
	return editServiceTmpl.Execute(w, r, data{nil, nil, "", tmp, nil})
}

func addAccountHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}
	tmp, err := config.ReadTemplate()
	if err != nil {
		return appErrorf(err, "could not read template: %v", err)
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
	if err := setStateToSession(w, r, state); err != nil {
		return err
	}
	engine, ok := engineMap[service.EngineName]
	if !ok {
		return appErrorf(err, "could not get engine: %v", err)
	}
	return editAccountTmpl.Execute(w, r, data{service, nil, authUrl, tmp, engine.Domains})
}

func saveServiceHandler(w http.ResponseWriter, r *http.Request) *appError {
	name := r.FormValue("PreviousServiceName")
	u, err := config.NewServiceUpdater(name)
	if err != nil {
		return appErrorf(err, "could not get service updater: %v", err)
	}

	session, e := cookieStore.Get(r, defaultSessionID)
	if e != nil {
		return appErrorf(e, "could not get default session: %v", e)
	}

	if err := u.Name(r.FormValue("ServiceName")); err != nil {
		session.AddFlash(fmt.Sprintf("%v", err))
		if err := session.Save(r, w); err != nil {
			return appErrorf(err, "could not save session: %v", err)
		}
		if name == "" {
			http.Redirect(w, r, "/portal/addservice", http.StatusFound)
			return nil
		} else {
			http.Redirect(w, r, fmt.Sprintf("/portal/editservice/%s", name), http.StatusFound)
			return nil
		}
	}

	u.ClientID(r.FormValue("ClientID"))
	u.ClientSecret(r.FormValue("ClientSecret"))

	engineName := r.FormValue("Engine")
	if engineName != "" {
		engine, err := engineFromRequest(engineName)
		if err != nil {
			return appErrorf(err, "could not find engine", err)
		}
		u.AuthURL(engine.AuthURL)
		u.TokenURL(engine.TokenURL)
		u.Scopes(engine.Scopes)
		u.EngineName(engineName)
	}

	if _, err := u.Commit(); err != nil {
		return appErrorf(err, "could not save changes: %v", err)
	}
	session.AddFlash(fmt.Sprintf("Successfully saved changes for service %s.", r.FormValue("ServiceName")))
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
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

	session, e := cookieStore.Get(r, defaultSessionID)
	if e != nil {
		return appErrorf(e, "could not get default session: %v", e)
	}
	if err := u.Name(r.FormValue("AccountName")); err != nil {
		session.AddFlash(fmt.Sprintf("%v", err))
		if err := session.Save(r, w); err != nil {
			return appErrorf(err, "could not save session: %v", err)
		}
		if previousAccount == "" {
			http.Redirect(w, r, fmt.Sprintf("/portal/addaccount/%s", sName), http.StatusFound)
			return nil
		} else {
			http.Redirect(w, r,
				fmt.Sprintf("/portal/editaccount/%s/%s", sName, previousAccount),
				http.StatusFound)
			return nil
		}
	}

	domainName := r.FormValue("Domain")
	if domainName != "" {
		u.ServiceURL(domainName)
	}

	s := session.Values[stateSessionKey]
	if s != nil {
		state, ok := s.(string)
		if !ok {
			return &appError{Message: "could not get state"}
		}
		code := r.FormValue("Code")
		if code != "" {
			decode, err := config.VerifyState(code, state)
			if err != nil {
				session.AddFlash("Oauth failed, please try again.")
				if err := session.Save(r, w); err != nil {
					return appErrorf(err, "could not save session: %v", err)
				}
				if previousAccount == "" {
					http.Redirect(w, r, fmt.Sprintf("/portal/addaccount/%s", sName), http.StatusFound)
					return nil
				} else {
					http.Redirect(w, r,
						fmt.Sprintf("/portal/reauthorizeaccount/%s/%s", sName, previousAccount),
						http.StatusFound)
					return nil
				}
			}

			if err := u.OauthCreds(decode); err != nil {
				return appErrorf(err, "could not update Oauth credentials: %v", err)
			}
		}
	}

	session.Values[stateSessionKey] = nil
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
	}

	if previousAccount == "" {
		if err := u.ClientCreds(); err != nil {
			return appErrorf(err, "could not generate client credentails: %v", err)
		}
	}

	i, err := u.Commit()
	if err != nil {
		return appErrorf(err, "could not save changes: %v", err)
	}
	a, ok := i.(*config.Account)
	if !ok {
		return appErrorf(err, "could not get account: %v", err)
	}

	// add new handler
	path, handler, err := createAccountHandler(u.C, u.C.Services[u.S], a)
	if err != nil {
		return appErrorf(err, "could not add handler for service: %s, account: %s, error: %v",
			u.C.Services[u.S].ServiceName, a.AccountName, err)
	}
	ServerHandlers.HandleFunc(path, handler)

	session.AddFlash(fmt.Sprintf("Successfully saved changes for account %s.", a.AccountName))
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
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

	session, _ := cookieStore.Get(r, defaultSessionID)
	session.AddFlash(fmt.Sprintf("Successfully removed service %s.", serviceStr))
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
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
	i, account, err := accountFromRequest(accountStr, service)
	if err != nil {
		return appErrorf(err, "could not find account: %v", err)
	}

	if err := config.RemoveAccount(i, sIdx); err != nil {
		return appErrorf(err, "could not delete account: %v", err)
	}

	// disable handler
	basePath := fmt.Sprintf("/service/%s/account/%s/", service.ServiceName, account.AccountName)
	ServerHandlers[basePath].Enabled = false

	session, _ := cookieStore.Get(r, defaultSessionID)
	session.AddFlash(fmt.Sprintf("Successfully removed account %s.", accountStr))
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
	}

	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
}

func removeUserHandler(w http.ResponseWriter, r *http.Request) *appError {
	userStr := mux.Vars(r)["user"]
	if err := config.RemoveUser(userStr); err != nil {
		return appErrorf(err, "could not delete user: %v", err)
	}

	session, _ := cookieStore.Get(r, defaultSessionID)
	session.AddFlash(fmt.Sprintf("Successfully removed user %s.", userStr))
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
	}

	http.Redirect(w, r, "/portal/users", http.StatusFound)
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
		return tmpl.Execute(w, r, data{service, nil, "", nil, nil})
	} else {
		accountStr := mux.Vars(r)["account"]
		_, account, err := accountFromRequest(accountStr, service)
		if err != nil {
			return appErrorf(err, "could not find account: %v", err)
		}
		engine, ok := engineMap[service.EngineName]
		if !ok {
			return appErrorf(err, "could not get engine: %v", err)
		}
		return tmpl.Execute(w, r, data{service, account, "", nil, engine.Domains})
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
	if err := setStateToSession(w, r, state); err != nil {
		return err
	}
	return editAccountTmpl.Execute(w, r, data{service, account, authUrl, nil, nil})
}

func listUserHandler(w http.ResponseWriter, r *http.Request) *appError {
	c, err := config.ReadConfig()
	if err != nil {
		return appErrorf(err, "could not read config file: %v", err)
	}
	return userTmpl.Execute(w, r, c.Users)
}

func addUserHandler(w http.ResponseWriter, r *http.Request) *appError {
	email := r.FormValue("Email")
	if err := config.AddUser(email); err != nil {
		return appErrorf(err, "could not add user: %v", err)
	}
	http.Redirect(w, r, "/portal/users", http.StatusFound)
	return nil
}

func uploadHandler(w http.ResponseWriter, r *http.Request) *appError {
	return uploadTmpl.Execute(w, r, nil)
}

func mappingHandler(w http.ResponseWriter, r *http.Request) *appError {
	f, _, err := r.FormFile("Mapping")
	if err != nil {
		http.Redirect(w, r, "/portal/upload", http.StatusFound)
		return nil
	}
	defer f.Close()
	var buf bytes.Buffer
	var t config.Template
	if _, err := io.Copy(&buf, f); err != nil {
		return appErrorf(err, "could not read file: %v", err)
	}
	err = json.Unmarshal(buf.Bytes(), &t)
	if err != nil {
		return appErrorf(err, "could not parse file: %v", err)
	}

	c, save, err := config.ReadWriteConfig()
	if err != nil {
		return appErrorf(err, "could not read config file", err)
	}

	c.Template = t
	if err = save(); err != nil {
		return appErrorf(err, "could not save to config file", err)
	}

	createMapping()

	http.Redirect(w, r, "/portal/", http.StatusFound)
	return nil
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

func engineFromRequest(engineStr string) (*config.Engine, error) {
	tmp, err := config.ReadTemplate()
	if err != nil {
		return nil, fmt.Errorf("Could not read template")
	}

	for _, e := range tmp.Engines {
		if engineStr == e.EngineName {
			return e, nil
		}
	}
	return nil, fmt.Errorf("No such engine: %s", engineStr)
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
		Path:     "/",
		MaxAge:   86400 * 7, // TODO: change to another duration?
		HttpOnly: true,
	}
	return store
}

func createMapping() {
	tmp, err := config.ReadTemplate()
	if err == nil {
		for _, engine := range tmp.Engines {
			engineMap[engine.EngineName] = engine
		}
	}
}

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

func flashFromSession(w http.ResponseWriter, r *http.Request) string {
	session, err := cookieStore.Get(r, defaultSessionID)
	if err != nil {
		return ""
	}
	var flash string
	var ok bool
	flashes := session.Flashes()
	if len(flashes) > 0 {
		if flash, ok = flashes[0].(string); !ok {
			return ""
		}
	}
	if err := session.Save(r, w); err != nil {
		return ""
	}
	return flash
}

func setStateToSession(w http.ResponseWriter, r *http.Request, state string) *appError {
	session, err := cookieStore.Get(r, defaultSessionID)
	if err != nil {
		return appErrorf(err, "could not get default session: %v", err)
	}
	session.Values[stateSessionKey] = state
	if err := session.Save(r, w); err != nil {
		return appErrorf(err, "could not save session: %v", err)
	}
	return nil
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
