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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"time"
)

var invalidKey = errors.New(
	"Could not parse account key.  It should look like: --accountKey=KEYBEGIN_service/account_abc123abc123abc123_KEYEND")

var missingKey = errors.New(
	"accountKey flag is required.  It should look like: --accountKey=KEYBEGIN_service/account_abc123abc123abc123_KEYEND")

var invalidHeaderFlag = errors.New(
	"Could not parse headers.  It should look like: \"someheader:value;otherheader:otherValue\"")

func main() {
	o, err := getOptions()
	if err != nil {
		fmt.Println(err)
		return
	}

	accountKey, err := parseKey(o.accountKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	privateKey, err := getPrivateKey(accountKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	t := createTransport(o.redirectAddr)

	fmt.Println("<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>")
	fmt.Println("<> Checking Web API Gateway status for given account key.")
	statusFullPath := path.Join("service", accountKey.service, "account", accountKey.account, "status")
	performRequest(accountKey, privateKey, t, statusFullPath, "GET", "", "")

	fmt.Println("<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>")
	fmt.Println("<> Performing specified connection test.")
	reqFullPath := path.Join("service", accountKey.service, "account", accountKey.account, "forward", o.path)
	performRequest(accountKey, privateKey, t, reqFullPath, o.method, o.body, o.headers)
}

func performRequest(accountKey *key, privateKey *ecdsa.PrivateKey, t http.RoundTripper, fullPath, method, body, headers string) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	signature, err := getSignature(privateKey, fullPath, timestamp, body)
	if err != nil {
		fmt.Println(err)
		return
	}

	url := strings.TrimRight(accountKey.WebGatewayUrl, "/") + "/" + strings.TrimLeft(fullPath, "/")

	r, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		fmt.Println(err)
		return
	}

	err = addHeaders(r.Header, signature, timestamp, headers)
	if err != nil {
		fmt.Println(err)
		return
	}

	d1, err := httputil.DumpRequestOut(r, true)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("===============================================================")
	fmt.Println("Request Sent")
	fmt.Println("================================")
	fmt.Printf("%s\n", d1)

	resp, err := t.RoundTrip(r)
	if err != nil {
		println("===============================")
		println("Error making request")
		println("=======================")
		fmt.Println(err)
		return
	}

	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		println("===============================")
		println("Error reading response")
		println("=======================")
		fmt.Println(err)
		// Print what we can anyways
	}

	fmt.Println("===============================================================")
	fmt.Println("Response Recieved")
	fmt.Println("================================")
	fmt.Printf("%s\n", dump)
}

type options struct {
	path         string
	accountKey   string
	headers      string
	body         string
	method       string
	redirectAddr string
}

func getOptions() (*options, error) {
	var o options
	flag.StringVar(&o.path, "path", "/", "The path after the domain in the url.")
	flag.StringVar(&o.accountKey, "accountKey", "", "Account key retrieved using the setup tool.")
	flag.StringVar(&o.headers, "headers", "", "how to use")
	flag.StringVar(&o.body, "body", "", "Body to send for PUT or POST methods.")
	flag.StringVar(&o.method, "method", "GET", "how to use")
	flag.StringVar(&o.redirectAddr, "redirectAddr", "", "how to use")
	flag.Parse()

	if o.accountKey == "" {
		return nil, missingKey
	}

	return &o, nil
}

type key struct {
	WebGatewayUrl string
	Protocol      string
	PrivateKey    string
	service       string
	account       string
}

func parseKey(accountKey string) (*key, error) {
	accountKey = strings.TrimSpace(accountKey)

	segments := strings.Split(accountKey, "_")
	if len(segments) != 4 || segments[0] != "KEYBEGIN" || segments[3] != "KEYEND" {
		return nil, invalidKey
	}

	b, err := base64.StdEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, invalidKey
	}

	var result key
	err = json.Unmarshal(b, &result)
	if err != nil {
		return nil, invalidKey
	}

	path := strings.Split(segments[1], "/")
	if len(path) != 2 {
		return nil, invalidKey
	}

	result.service = path[0]
	result.account = path[1]

	if result.WebGatewayUrl == "" || result.Protocol == "" || result.PrivateKey == "" {
		return nil, invalidKey
	}

	return &result, nil
}

func getPrivateKey(key string) (*ecdsa.PrivateKey, error) {
	fmt.Println("-------------------------=-=-=-=")
	fmt.Println(key)
	fmt.Println("-------------------------=-=-=-=")
	der, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	switch privateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return privateKey, nil
	}

	return nil, errors.New("Private key not of type ecdsa")
}

func getSignature(privateKey *ecdsa.PrivateKey, url, timestamp, body string) (string, error) {
	signed := make([]byte, 0)
	signed = append(signed, []byte("/")...)
	signed = append(signed, []byte(strings.TrimLeft(url, "/"))...)
	signed = append(signed, []byte("\n")...)
	signed = append(signed, []byte(timestamp)...)
	signed = append(signed, []byte("\n")...)
	signed = append(signed, body...)

	hash := sha256.Sum256(signed)

	rawSig := struct {
		R, S *big.Int
	}{}

	var err error
	rawSig.R, rawSig.S, err = ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	b, err := asn1.Marshal(rawSig)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func addHeaders(header http.Header, signature, timestamp, fromFlag string) error {
	header.Set("For-Web-Api-Gateway-Signature", signature)
	header.Set("For-Web-Api-Gateway-Request-Time-Utc", timestamp)
	if fromFlag == "" {
		return nil
	}

	pairs := strings.Split(fromFlag, ";")
	for _, pair := range pairs {
		split := strings.SplitN(pair, ":", 2)
		if len(split) != 2 {
			return invalidHeaderFlag
		}
		header.Set(split[0], split[1])
	}
	return nil
}

func createTransport(redirectAddr string) http.RoundTripper {
	if redirectAddr == "" {
		return http.DefaultTransport
	}

	dialer := &net.Dialer{}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, redirectAddr)
	}

	return &http.Transport{
		DialContext: dialFunc,
	}
}
