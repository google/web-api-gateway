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
	"crypto/sha256"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

// As a matter of policy, changes to this file should be security reviewed,
// while changes to other files are less likely to need it.

func onlyAllowVerifiedRequests(
	handler http.Handler, key *ecdsa.PublicKey, now func() time.Time) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		signatureR, goodParse := big.NewInt(0).SetString(r.Header.Get("For-Web-Api-Gateway-Auth-R"), 10)
		if !goodParse {
			ErrorInvalidHeaders.ServeHTTP(w, r)
			return
		}
		signatureS, goodParse := big.NewInt(0).SetString(r.Header.Get("For-Web-Api-Gateway-Auth-S"), 10)
		if !goodParse {
			ErrorInvalidHeaders.ServeHTTP(w, r)
			return
		}

		timestamp, err := strconv.ParseInt(r.Header.Get("For-Web-Api-Gateway-Request-Time-Utc"), 10, 64)
		if err != nil {
			ErrorInvalidHeaders.ServeHTTP(w, r)
			return
		}
		timeError := time.Unix(timestamp, 0).Sub(now()).Minutes()
		if timeError > 1 || timeError < -1 {
			ErrorInvalidTime.ServeHTTP(w, r)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			ErrorIO.ServeHTTP(w, r)
			return
		}

		hash := sha256.New()
		hash.Write([]byte(r.URL.String()))
		hash.Write([]byte(r.Header.Get("For-Web-Api-Gateway-Request-Time-Utc")))
		hash.Write(body)

		if ecdsa.Verify(key, hash.Sum(nil), signatureR, signatureS) {
			r2 := new(http.Request)
			*r2 = *r
			r2.Body = ioutil.NopCloser(bytes.NewBuffer(body))

			// TODO: Also clean out headers beginning with "For-Web-Api-Gateway"

			handler.ServeHTTP(w, r2)
			return
		}

		ErrorNotVerified.ServeHTTP(w, r)
	}
}
