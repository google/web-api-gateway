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

package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var configFileName *string = flag.String(
	"configpath",
	"/etc/webapigateway/config/config.json",
	"This is the path to the json config file managing this proxy.",
)

func ReadConfig() (*Config, error) {
	return readConfig(*configFileName)
}

func ReadWriteConfig() (c *Config, save func() error, err error) {
	return readWriteConfig(*configFileName)
}

func ReadTemplate() (*Template, error) {
	c, err := readConfig(*configFileName)
	if err != nil {
		return nil, err
	}
	return &c.Template, nil
}

func readConfig(name string) (*Config, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", name, err)
	}

	c := Config{}
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, fmt.Errorf("error parsing json in file %s: %v", name, err)
	}
	return &c, nil
}

func readWriteConfig(name string) (c *Config, save func() error, err error) {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_SYNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading or creating file %s: %v", name, err)
	}

	c = &Config{}
	{
		b, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading file %s: %v", name, err)
		}

		if len(b) > 0 {
			err = json.Unmarshal(b, &c)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing json in file %s: %v", name, err)
			}
		}
	}

	return c, saveConfig(name, c, f), nil
}

func saveConfig(name string, c *Config, f *os.File) func() error {
	return func() error {
		defer f.Close()

		b, err := json.MarshalIndent(&c, "", "  ")
		if err != nil {
			return fmt.Errorf("Changes were not saved! Error making json: %v", err)
		}

		_, err = f.WriteAt(b, 0)
		if err != nil {
			return fmt.Errorf("Changes may not be not saved! Error writing to file %s: %v", name, err)
		}

		err = f.Truncate(int64(len(b)))
		if err != nil {
			return fmt.Errorf("Changes may not be not saved! Error writing to file %s: %v", name, err)
		}

		return nil
	}
}
