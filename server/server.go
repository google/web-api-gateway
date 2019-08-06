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
	"crypto/tls"
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
	"sync"
	"time"

	option "google.golang.org/api/option"
	plus "google.golang.org/api/plus/v1"

	"github.com/google/web-api-gateway/config"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// trying to addddd some feeeeee
const version = "2.1.0"

// TODO: switch to some other time interval?
const reloadInterval = time.Minute * 30

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

var listName *string = flag.String(
	"list",
	"/go/src/github.com/google/web-api-gateway/server/templates/list.html",
	"This is list.html.",
)

var editServiceName *string = flag.String(
	"editService",
	"/go/src/github.com/google/web-api-gateway/server/templates/editService.html",
	"This is editService.html.",
)

var editAccountName *string = flag.String(
	"editAccount",
	"/go/src/github.com/google/web-api-gateway/server/templates/editAccount.html",
	"This is editAccount.html.",
)

func main() {
	flag.Parse()

	log.Println("Reading config file...")

	////////////// below three should be not working :/
	// TODO: move to use gorilla mux or
	http.Handle("/service/", createConfigHandler())
	http.HandleFunc("/authToken/", authTokenPage)
	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "web-api-gateway version: %s\nGo version: %s", version, runtime.Version())
	})

	sine := sineRegisterHandlers()

	log.Printf("Starting web-api-gateway, version %s\n", version)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Incoming Request %s %s %s", r.RemoteAddr, r.Method, r.URL)
		sine.ServeHTTP(w, r)
	})

	cr, err := NewCertificateReloader(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr: ":https",
		TLSConfig: &tls.Config{
			GetCertificate: cr.GetCertificateFunc(),
		},
		Handler: mux,
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

//////////////////////////////////////////////////
/////////////////////////////////////////////////
var (
	baseTmpl        = parseTemplate("")
	listTmpl        = parseTemplate(*listName)
	editServiceTmpl = parseTemplate(*editServiceName)
	editAccountTmpl = parseTemplate(*editAccountName)
)

var oauthConf *oauth2.Config = &oauth2.Config{
	ClientID:     "523939206127-3pr1qbrn0g78l6r9nu10l733q9obgn0t.apps.googleusercontent.com",
	ClientSecret: "zKY48Os4L8xKAuQoiBFqrLkW",
	Scopes:       []string{"email", "profile"},
	Endpoint:     google.Endpoint,
}

var whites []*profile

type data struct {
	Service *config.Service
	Account *config.Account
}

type profile struct {
	ID, DisplayName, ImageURL string
	Emails          []*plus.PersonEmails
}

func sineRegisterHandlers() *mux.Router {
	r := mux.NewRouter()

	r.Methods("GET").Path("/").HandlerFunc(baseHandler)

	r.Methods("GET").Path("/portal/").HandlerFunc(listHandler)
	r.Methods("GET").Path("/portal/addservice").HandlerFunc(addServiceHandler)
	r.Methods("GET").Path("/portal/editservice/{service}").HandlerFunc(editServiceHandler)
	r.Methods("GET").Path("/portal/removeservice/{service}").HandlerFunc(removeServiceHandler)

	r.Methods("GET").Path("/portal/editaccount/{service}/{account}").HandlerFunc(editAccountHandler)

	r.Methods("POST").Path("/portal/saveservice").HandlerFunc(saveServiceHandler)
	r.Methods("POST").Path("/portal/saveaccount").HandlerFunc(saveAccountHandler)

	//////////////////////////////
	// modifying already exisiting handlers
	r.Methods("GET").Path("/version").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "web-api-gateway version: %s\nGo version: %s", version, runtime.Version())
	})

	// auth related handlers
	r.Methods("GET").Path("/login").HandlerFunc(loginHandler)
	r.Methods("GET").Path("/auth").HandlerFunc(oauthCallbackHandler)

	return r
}

func baseHandler(w http.ResponseWriter, r *http.Request) {
	baseTmpl.Execute(w, r, nil)
}

// loginHandler initiates an OAuth flow to the Google+ API
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// ctx := context.Background()
	// creds, err := google.FindDefaultCredentials(ctx, plus.UserinfoProfileScope, plus.PlusLoginScope,
	// 	plus.PlusMeScope, plus.UserinfoEmailScope)
	//  if err != nil {
	//  	log.Printf("Can't get default creds")
	//  	return
	//  }
	// 	b, err := ioutil.ReadFile("/go/src/github.com/google/web-api-gateway/credentials.json")
	// 	if err != nil {
	// 		log.Printf("unable to read file")
	// 		return
	// 	}
	// 	log.Println(b)
	// oauthConf, err := google.ConfigFromJSON(b, plus.UserinfoProfileScope, plus.PlusLoginScope,
	// 	plus.PlusMeScope, plus.UserinfoEmailScope)
	// if err != nil {
	// 	log.Printf("Can't get Oauthconfig from default creds")
	// 	return
	// }
	// {"web":{"client_id":"523939206127-3pr1qbrn0g78l6r9nu10l733q9obgn0t.apps.googleusercontent.com",
	// "project_id":"ds-gateway-test",
	// "auth_uri":"https://accounts.google.com/o/oauth2/auth",
	// "token_uri":"https://oauth2.googleapis.com/token",
	// "auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
	// "client_secret":"zKY48Os4L8xKAuQoiBFqrLkW",
	// "javascript_origins":["http://test-web-api-gateway.sriramkp.com"]}}
	c, err := config.ReadConfig()
	if err != nil {
		log.Printf("Error reading config file: %s", err)
		ErrorReadingConfig.ServeHTTP(w, r)
		return
	}
	redirectUrl, err := url.Parse(c.Url)
	if err != nil {
		log.Printf("Can't parse URL.")
		return
	}
	redirectUrl.Path = "/auth"
	oauthConf.RedirectURL = redirectUrl.String()
	url := oauthConf.AuthCodeURL("state", oauth2.ApprovalForce)
	// log.Println(url)
	http.Redirect(w, r, url, http.StatusFound)
}

func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	// // add correct scope
	// oauthClient, err := google.DefaultClient(ctx, plus.UserinfoProfileScope, plus.PlusLoginScope,
	// 	plus.PlusMeScope, plus.UserinfoEmailScope)
	// if err != nil {
	// 	log.Printf("Can't get default oauth")
	// 	return
	// }
	// plusService, err := plus.NewService(ctx, option.WithHTTPClient(oauthClient))

	// // creds, err := google.FindDefaultCredentials(ctx, plus.UserinfoProfileScope, plus.PlusLoginScope,
	// // 	plus.PlusMeScope, plus.UserinfoEmailScope)
	// //  if err != nil {
	// //  	log.Printf("Can't get default creds")
	// //  	return
	// //  }
	// // plusService, err := plus.NewService(ctx, option.WithCredentials(creds))
	// if err != nil {
	// 	log.Printf("Can't create plus service.")
	// 	return
	// }
	// profile, err := plusService.People.Get("me").Do()
	// if err != nil {
	// 	log.Printf("Can't fetch Google profiles: %s", err)
	// 	return
	// }
	// log.Printf("profile is: %s", *stripProfile(profile))
	code := r.FormValue("code")
	tok, err := oauthConf.Exchange(ctx, code)
	if err != nil {
		log.Printf("Could not get auth token")
		return
	}
	plusService, err := plus.NewService(ctx, option.WithTokenSource(oauthConf.TokenSource(ctx, tok)))
	if err != nil {
		log.Printf("Could not get plus service")
		return
	}
	person, err := plusService.People.Get("me").Do()
	if err != nil {
		log.Printf("Can't fetch Google profiles: %s", err)
		return
	}
	profile := stripProfile(person)
	log.Printf("id is: %s, name is: %s, emails are : %s", profile.ID, profile.DisplayName, profile.Emails)
	whites = append(whites, profile)
	http.Redirect(w, r, fmt.Sprintf("/portal/"), http.StatusFound)
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	c, err := config.ReadConfig()
	if err != nil {
		log.Printf("Error reading config file: %s", err)
		ErrorReadingConfig.ServeHTTP(w, r)
		return
	}
	listTmpl.Execute(w, r, *c)
}

func editServiceHandler(w http.ResponseWriter, r *http.Request) {
	editHandler(w, r, editServiceTmpl)
}

func editAccountHandler(w http.ResponseWriter, r *http.Request) {
	editHandler(w, r, editAccountTmpl)
}

func addServiceHandler(w http.ResponseWriter, r *http.Request) {
	editServiceTmpl.Execute(w, r, nil)
}

func saveServiceHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("PreviousServiceName")
	u, err := config.NewServiceUpdater(name)
	if err != nil {
		log.Printf("Error getting updater: %s", err)
		return
	}
	// e := userInput(r.FormValue("ServiceName"), u.Name) +
	// userInput(r.FormValue("ClientID"), u.ClientID)
	// TODO: add validations?????
	// TODO: **** rename would break exsiting connections, so maybe pop-up?
	u.Name(r.FormValue("ServiceName"))
	u.ClientID(r.FormValue("ClientID"))
	u.ClientSecret(r.FormValue("ClientSecret"))
	u.AuthURL(r.FormValue("AuthURL"))
	u.TokenURL(r.FormValue("TokenURL"))
	u.Scopes(r.FormValue("Scopes"))
	if u.Commit() != nil {
		log.Printf("Error when saving")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/portal/"), http.StatusFound)
}

func saveAccountHandler(w http.ResponseWriter, r *http.Request) {
	// sName := r.FormValue("ServiceName")
	// aName := r.FormValue("PreviousAccountName")
	// u, err := config.NewServiceUpdater(sName)
	// if err != nil {
	// 	log.Printf("Error getting updater: %s", err)
	// 	return
	// }

	// c, err := config.ReadConfig()
	// if err != nil {
	// 	log.Printf("Error reading config file: %s", err)
	// 	ErrorReadingConfig.ServeHTTP(w, r)
	// 	return
	// }
	// TODO: if err!=nil
	// _, service, err := serviceFromRequest(sName, c)
	// i, account, err := accountFromRequest(aName, service)
	// log.Println(i)
	// u.Account(i, account)
	// if u.Commit() != nil {
	// 	log.Printf("Error when saving")
	// 	return
	// }
	http.Redirect(w, r, fmt.Sprintf("/portal/"), http.StatusFound)
}

func removeServiceHandler(w http.ResponseWriter, r *http.Request) {
	// jian lve??
	c, err := config.ReadConfig()
	if err != nil {
		log.Printf("Error reading config file: %s", err)
		ErrorReadingConfig.ServeHTTP(w, r)
		return
	}

	serviceStr := mux.Vars(r)["service"]
	i, _, err := serviceFromRequest(serviceStr, c)
	if err != nil {
		log.Printf("Error finding service : %s", err)
		// adding another error?
		return
	}
	log.Println(i)
	config.SetServices(append(c.Services[:i], c.Services[i+1:]...))

	http.Redirect(w, r, fmt.Sprintf("/portal/"), http.StatusFound)
}

func editHandler(w http.ResponseWriter, r *http.Request, tmpl *appTemplate) {
	c, err := config.ReadConfig()
	if err != nil {
		log.Printf("Error reading config file: %s", err)
		ErrorReadingConfig.ServeHTTP(w, r)
		return
	}

	serviceStr := mux.Vars(r)["service"]
	_, service, err := serviceFromRequest(serviceStr, c)
	if err != nil {
		log.Printf("Error finding service: %s", err)
		// TODO:
		// adding another error?
		return
	}
	if tmpl == editServiceTmpl {
		tmpl.Execute(w, r, service)
	} else {
		accountStr := mux.Vars(r)["account"]
		_, account, err := accountFromRequest(accountStr, service)
		if err != nil {
			log.Printf("Error finding account: %s", err)
			return
		}
		tmpl.Execute(w, r, data{service, account})
	}
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
		ID:          p.Id,
		DisplayName: p.DisplayName,
		ImageURL: p.Image.Url,
	}
}

// func userInput(value string, handler func(string) error) string {
// 		err := handler(value)
// 		if err != nil {
// 			return err.Error
// 		}
// 		return nil
// }

// type appHandler func(http.ResponseWriter, *http.Request)

// func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	fn(w, r)
// }

////////////////////////////////////////////////
///////////////////////////////////////////////

///////////////////////////////////////////////
type certificateReloader struct {
	sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func NewCertificateReloader(certPath, keyPath string) (*certificateReloader, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	result := &certificateReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	result.cert = &cert

	tickerChannel := time.NewTicker(reloadInterval).C

	go func() {
		for range tickerChannel {
			log.Printf("Reloading TLS certificate and key from %s and %s", certPath, keyPath)
			if err := result.maybeReload(); err != nil {
				log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
			}
		}
	}()

	return result, nil
}

func (cr *certificateReloader) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
	if err != nil {
		return err
	}
	cr.Lock()
	defer cr.Unlock()
	cr.cert = &newCert

	log.Printf("Reloaded certificate successfully!")

	return nil
}

func (cr *certificateReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cr.RLock()
		defer cr.RUnlock()
		return cr.cert, nil
	}
}

///////////////////////////////////////////

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
			r.Header[ClientIdHeader] = []string{service.OauthServiceCreds.ClientID}
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
	err := r.ParseForm()
	if handleAuthTokenPageError(w, err) {
		return
	}

	if r.FormValue("error") != "" {
		_, err := fmt.Fprintf(
			w,
			"The authenticating service returned an error, code='%s', details='%s'.",
			r.FormValue("error"),
			r.FormValue("error_description"))

		handleAuthTokenPageError(w, err)
		return
	}

	response := struct {
		Token string
		State string
	}{
		Token: r.FormValue("code"),
		State: r.FormValue("state"),
	}

	if response.Token == "" {
		_, err = fmt.Fprintf(w, "Missing required form value 'code'")
		handleAuthTokenPageError(w, err)
		return
	}

	if response.State == "" {
		_, err = fmt.Fprintf(w, "Missing required form value 'state'")
		handleAuthTokenPageError(w, err)
		return
	}

	b, err := json.Marshal(response)
	if handleAuthTokenPageError(w, err) {
		return
	}

	_, err = fmt.Fprintf(
		w,
		"Copy-paste this code into the setup tool: %s",
		base64.StdEncoding.EncodeToString(b))

	if handleAuthTokenPageError(w, err) {
		return
	}
}

func handleAuthTokenPageError(w http.ResponseWriter, err error) bool {
	if err != nil {
		// Ignore error writing this out, we're already in a bad state.
		w.Write([]byte("Error generating response.  It has been logged."))
		log.Println("Error generating authToken response:", err)
		return true
	}
	return false
}
