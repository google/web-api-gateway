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
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
)

// var baseName *string = flag.String(
// 	"base",
// 	"/go/src/github.com/google/web-api-gateway/server/templates/base.html",
// 	"This is base.html.",
// )

var templatesFolder *string = flag.String(
	"templatesfolder",
	"/go/src/github.com/google/web-api-gateway/server/templates/",
	"This is the path for the templates folder.",
)

// parseTemplate applies a given file to the body of the base template.
func parseTemplate(filename string) *appTemplate {
	tmpl := template.Must(template.ParseFiles(*templatesFolder + "base.html"))
	tmpl.New("body").Parse("\n")
	if filename != "" {
		b, err := ioutil.ReadFile(filename)
		if err != nil {
			panic(fmt.Errorf("could not read template: %v", err))
		}
		template.Must(tmpl.Lookup("body").Parse(string(b)))
	}

	return &appTemplate{tmpl.Lookup("base.html")}
}

// appTemplate is a user login-aware wrapper for a html/template.
type appTemplate struct {
	t *template.Template
}

// Execute writes the template using the provided data, adding login and user
// information to the base template.
func (tmpl *appTemplate) Execute(w http.ResponseWriter, r *http.Request, data interface{}) {
	d := struct {
		Data    interface{}
		Profile *profile
		// LoginURL    string
		// LogoutURL   string
	}{
		Data: data,
		// LoginURL:    "/login?redirect=" + r.URL.RequestURI(),
		// LogoutURL:   "/logout?redirect=" + r.URL.RequestURI(),
	}
	if r.URL.RequestURI() != "/" {
		d.Profile = whites[0]
	}
	// // log.Println(d)
	// // if d.AuthEnabled {
	// //   // Ignore any errors.
	// //   d.Profile = profileFromSession(r)
	// // }

	if err := tmpl.t.Execute(w, d); err != nil {
		log.Printf("could not write template: %v", err)
	}
	// log.Println(tmpl.t.DefinedTemplates())
	return
}
