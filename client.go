package keygen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	// APIVersion is the currently supported API version.
	APIVersion string = "v1"

	// APIURL is the URL of the API service backend.
	APIURL string = "https://api.keygen.sh"

	userAgent = "Keygen SDK (lang=go)"
)

type client struct {
	account string
	product string
	token   string
}

func (c client) Post(path string, data interface{}) (*http.Response, error) {
	return c.request("POST", path, data)
}

func (c client) Get(path string, data interface{}) (*http.Response, error) {
	return c.request("GET", path, data)
}

func (c client) Put(path string, data interface{}) (*http.Response, error) {
	return c.request("PUT", path, data)
}

func (c client) Patch(path string, data interface{}) (*http.Response, error) {
	return c.request("PATCH", path, data)
}

func (c client) Delete(path string, data interface{}) (*http.Response, error) {
	return c.request("DELETE", path, data)
}

func (c client) request(method string, path string, data interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s/accounts/%s/%s", APIURL, APIVersion, c.account, path)
	params, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	body := bytes.NewBuffer(params)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", userAgent)

	api := new(http.Client)
	res, err := api.Do(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}
