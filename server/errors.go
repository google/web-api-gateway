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

import "net/http"

type errorCode struct {
	httpStatus int
	s          string
}

func (e *errorCode) String() string {
	return e.s
}

func (e *errorCode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("From-Web-Api-Gateway-Was-Error", "true")
	w.Header().Set("From-Web-Api-Gateway-Error-Code", e.String())
	w.WriteHeader(e.httpStatus)
}

var (
	ErrorInvalidHeaders     = &errorCode{http.StatusBadRequest, "ErrorInvalidHeaders"}
	ErrorInvalidSignature   = &errorCode{http.StatusBadRequest, "ErrorInvalidSignature"}
	ErrorInvalidTime        = &errorCode{http.StatusBadRequest, "ErrorInvalidTime"}
	ErrorIO                 = &errorCode{http.StatusInternalServerError, "ErrorIO"}
	ErrorEncodingStatusJson = &errorCode{http.StatusInternalServerError, "ErrorEncodingStatusJson"}
	ErrorParsingRedirectUrl = &errorCode{http.StatusInternalServerError, "ErrorParsingRedirectUrl"}
	ErrorReadingConfig      = &errorCode{http.StatusInternalServerError, "ErrorReadingConfig"}
	ErrorNotVerified        = &errorCode{http.StatusUnauthorized, "ErrorNotVerified"}
)
