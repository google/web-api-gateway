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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var privateKey *ecdsa.PrivateKey

var alternateNow = func() time.Time {
	return time.Unix(904867200, 0)
}

func init() {
	var err error
	// This is a horribly insecure way to create a key, only good for creating a
	// well known key for testing!
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.New(rand.NewSource(0)))
	if err != nil {
		panic(err)
	}
}

func createSignature(t *testing.T) string {
	digest := "https://www.proxy.com/some/path\n" + "904867200\n" + "request body"
	sum := sha256.Sum256([]byte(digest))

	r, s, err := ecdsa.Sign(rand.New(rand.NewSource(0)), privateKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	return encodeAsn1Signature(r, s, t)
}

func encodeAsn1Signature(r, s *big.Int, t *testing.T) string {
	asn1Sig := struct {
		R, S *big.Int
	}{
		r, s,
	}

	b, err := asn1.Marshal(asn1Sig)
	if err != nil {
		t.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(b)
}

func createRequest(t *testing.T) *http.Request {
	body := bytes.NewBuffer([]byte("request body"))

	r := httptest.NewRequest("POST", "https://www.proxy.com/some/path", body)
	r.Header.Set("For-Web-Api-Gateway-Signature", createSignature(t))
	r.Header.Set("For-Web-Api-Gateway-Request-Time-Utc", "904867200")

	return r
}

func checkExpectations(t *testing.T, resp *http.Response, status int, body, wasError, errorCode string) {
	actualBody, _ := ioutil.ReadAll(resp.Body)

	if status != resp.StatusCode {
		t.Errorf("statusCode expected: %d actual: %d", status, resp.StatusCode)
	}
	if body != string(actualBody) {
		t.Errorf("body expected: %s actual: %s", body, string(actualBody))
	}
	if wasError != resp.Header.Get("From-Web-Api-Gateway-Was-Error") {
		t.Errorf("From-Web-Api-Gateway-Was-Error expected: %s actual: %s", wasError, resp.Header.Get("From-Web-Api-Gateway-Was-Error"))
	}
	if errorCode != resp.Header.Get("From-Web-Api-Gateway-Error-Code") {
		t.Errorf("From-Web-Api-Gateway-Error-Code expected: %s actual: %s", errorCode, resp.Header.Get("From-Web-Api-Gateway-Error-Code"))
	}
}

func fatalHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Error("The handler should not be called!")
	}
}

func TestGoodAuth(t *testing.T) {
	successHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(body) != "request body" {
			t.Errorf("request body expected: %s actual: %s", "request body", string(body))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success!"))
	})

	handler := onlyAllowVerifiedRequests(successHandler, &privateKey.PublicKey, alternateNow)

	req := createRequest(t)
	w := httptest.NewRecorder()
	handler(w, req)

	checkExpectations(t, w.Result(), http.StatusOK, "Success!", "", "")
}

func TestNonAsn1Signature(t *testing.T) {
	handler := onlyAllowVerifiedRequests(fatalHandler(t), &privateKey.PublicKey, alternateNow)

	req := createRequest(t)
	req.Header.Set("For-Web-Api-Gateway-Signature", "thisisn'tgoingtowork")
	w := httptest.NewRecorder()
	handler(w, req)

	checkExpectations(t, w.Result(), http.StatusBadRequest, "", "true", "ErrorInvalidHeaders")
}

func TestNonNumericTimestamp(t *testing.T) {
	handler := onlyAllowVerifiedRequests(fatalHandler(t), &privateKey.PublicKey, alternateNow)

	req := createRequest(t)
	req.Header.Set("For-Web-Api-Gateway-Request-Time-Utc", "thisisn'tgoingtowork")
	w := httptest.NewRecorder()
	handler(w, req)

	checkExpectations(t, w.Result(), http.StatusBadRequest, "", "true", "ErrorInvalidHeaders")
}

func TestIncorrectSignature(t *testing.T) {
	handler := onlyAllowVerifiedRequests(fatalHandler(t), &privateKey.PublicKey, alternateNow)

	req := createRequest(t)
	sig := encodeAsn1Signature(big.NewInt(5), big.NewInt(6), t)
	req.Header.Set("For-Web-Api-Gateway-Signature", sig)
	w := httptest.NewRecorder()
	handler(w, req)

	checkExpectations(t, w.Result(), http.StatusUnauthorized, "", "true", "ErrorNotVerified")
}

func TestOldTimestamp(t *testing.T) {
	handler := onlyAllowVerifiedRequests(fatalHandler(t), &privateKey.PublicKey, func() time.Time {
		return time.Unix(904867200+61, 0)
	})

	req := createRequest(t)
	w := httptest.NewRecorder()
	handler(w, req)

	checkExpectations(t, w.Result(), http.StatusBadRequest, "", "true", "ErrorInvalidTime")
}

func TestEarlyTimestamp(t *testing.T) {
	handler := onlyAllowVerifiedRequests(fatalHandler(t), &privateKey.PublicKey, func() time.Time {
		return time.Unix(904867200-61, 0)
	})

	req := createRequest(t)
	w := httptest.NewRecorder()
	handler(w, req)

	checkExpectations(t, w.Result(), http.StatusBadRequest, "", "true", "ErrorInvalidTime")
}
