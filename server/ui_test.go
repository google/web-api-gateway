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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var client *http.Client
var host string

func TestMain(m *testing.M) {
	serv := httptest.NewServer(nil)
	client = http.DefaultClient
	host = serv.Listener.Addr().String()
	mux := UIHandlers()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	})

	fmt.Println("test server up, host is: " + host)

	os.Exit(m.Run())
}

func TestNoServices(t *testing.T) {
	bodyContains(t, "/portal/", "No services yet")
}

func createServerRequest(t *testing.T) *http.Request {

	r := httptest.NewRequest("", "https://www.proxy.com/some/path", nil)
	return r
}

func bodyContains(t *testing.T, path, contains string) (ok bool) {
	body, _, err := getBody(path)
	if err != nil {
		t.Error(err)
		return false
	}
	if !strings.Contains(body, contains) {
		t.Errorf("want %s to contain %s", body, contains)
		return false
	}
	return true
}

func getBody(path string) (body string, resp *http.Response, err error) {
	resp, err = client.Get("http://" + host + path)
	if err != nil {
		return "", resp, err
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", resp, err
	}
	return string(b), resp, err
}
