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

/*
This implements a very minimal test server.  It fakes an implementation of
oauth2, so that the setup process can be verified.  It also implements some
endpoints that require authentication, so that basic interaction can be tested.
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

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

const ClientID = "ID"
const ClientSecret = "SECRET"
const AuthorizationToken = "AuthorizationToken"
const RefreshToken = "RefreshToken2"
const AccessToken = "AccessToken2"

func main() {
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/auth", auth)
	mux.HandleFunc("/oauth/token", token)

	mux.Handle("/service/hello", behindAuth(createTestPage("Hello World.")))
	mux.Handle("/service/redirect1", behindAuth(createTestRedirect("https://localhost:2157/service/redirect3")))

	log.Println("Starting server...")
	go secondServer()
	log.Fatal(http.ListenAndServeTLS(":2156", *certFile, *keyFile, logAllRequests("2156", mux)))
}

func secondServer() {
	mux := http.NewServeMux()
	mux.Handle("/service/redirect3", createTestRedirect("https://localhost:2157/service/redirect4"))
	mux.Handle("/service/redirect4", createTestPage("I was certainly redirected."))

	log.Fatal(http.ListenAndServeTLS(":2157", *certFile, *keyFile, logAllRequests("2157", mux)))
}

func token(w http.ResponseWriter, r *http.Request) {
	{
		b, err := httputil.DumpRequest(r, true)
		fmt.Println(err)
		fmt.Printf("%s\n", string(b))
	}
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}

	switch r.FormValue("grant_type") {
	case "authorization_code":
		assertFormValue(r, "code", AuthorizationToken)
	case "refresh_token":
		assertFormValue(r, "refresh_token", RefreshToken)
	default:
		panic(fmt.Sprintf("unknown grant_type: %s", r.FormValue("grant_type")))
	}
	w.Header().Set("Content-Type", "text/json")
	writeJson(w, map[string]interface{}{
		"access_token":  AccessToken,
		"refresh_token": RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
	})
}

func assertFormValue(r *http.Request, field, expected string) {
	if r.FormValue(field) != expected {
		panic(fmt.Sprintf("Form value %s expected '%s', but was '%s'", field, expected, r.FormValue(field)))
	}
}

func writeJson(w http.ResponseWriter, v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	fmt.Println("======")
	fmt.Println(string(b))
	fmt.Println("======")
	_, err = w.Write(b)
	if err != nil {
		panic(err)
	}
}

func auth(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}

	assertFormValue(r, "client_id", ClientID)
	assertFormValue(r, "response_type", "code")
	assertFormValue(r, "scope", "testscope")

	uri := r.FormValue("redirect_uri")
	state := r.FormValue("state")

	rUri := fmt.Sprintf("%s?state=%s&code=%s", uri, state, AuthorizationToken)

	http.Redirect(w, r, rUri, http.StatusTemporaryRedirect)
}

func createTestPage(text string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Printing test page: ", text)
		w.Write([]byte(text))
	})
}

func createTestRedirect(redirectUrl string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Redirecting to: ", redirectUrl)
		http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
	})
}

func behindAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expected := "Bearer " + AccessToken
		log.Println("Verifying auth")
		if authHeader != expected {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("Auth header expected '%s', but was '%s'\n", expected, authHeader)
			return
		}
		log.Println("Verified.")
		h.ServeHTTP(w, r)
	})
}

func logAllRequests(server string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		{
			b, err := httputil.DumpRequest(r, true)
			log.Printf("============= Incoming Request to %s\nLogging Error: %s\nRequest:\n%s\n", server, err, string(b))
		}
		h.ServeHTTP(w, r)
	})

}
