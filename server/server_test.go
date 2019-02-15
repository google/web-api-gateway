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
	"io/ioutil"
	"net/http/httptest"
	"testing"
)

func performTest(t *testing.T, parameters, expected string) {
	r := httptest.NewRequest("GET", "https://www.proxy.com/authToken/?"+parameters, nil)
	w := httptest.NewRecorder()

	authTokenPage(w, r)

	b, _ := ioutil.ReadAll(w.Body)
	actual := string(b)

	if expected != actual {
		t.Errorf("body expected: %s actual: %s", expected, actual)
	}
}

func TestAuthTokenPage(t *testing.T) {
	performTest(t, "", "Missing required form value 'code'")
	performTest(t, "code=123", "Missing required form value 'state'")
	performTest(t, "code=123&state=456", "Copy-paste this code into the setup tool: eyJUb2tlbiI6IjEyMyIsIlN0YXRlIjoiNDU2In0=")
	performTest(t, "error=foo&error_description=not%20this", "The authenticating service returned an error, code='foo', details='not this'.")
}
