package keygen

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"

	"github.com/google/go-querystring/query"
	"github.com/pieoneers/jsonapi-go"
)

const (
	APIURL     = "https://api.keygen.sh"
	APIVersion = "v1"

	sdkVersion = "1.0.0"
)

var (
	userAgent = "keygen/" + APIVersion + " sdk/" + sdkVersion + " go/" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	client    = &http.Client{
		// We don't want to automatically follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

const (
	ErrorCodeTokenInvalid     = "TOKEN_INVALID"
	ErrorCodeNotFound         = "NOT_FOUND"
	ErrorCodeMachineDead      = "MACHINE_DEAD"
	ErrorCodeFingerprintTaken = "FINGERPRINT_TAKEN"
)

var (
	ErrLicenseTokenInvalid     = errors.New("authentication token is invalid")
	ErrMachineAlreadyActivated = errors.New("machine is already activated")
	ErrMachineDead             = errors.New("machine does not exist")
	ErrNotFound                = errors.New("resource does not exist")
)

type Client struct {
	account string
	token   string
}

type Response struct {
	Headers http.Header
	Body    []byte
	Status  int
}

func (c *Client) Post(path string, params interface{}) (*Response, error) {
	return c.send("POST", path, params)
}

func (c *Client) Get(path string, params interface{}) (*Response, error) {
	return c.send("GET", path, params)
}

func (c *Client) Put(path string, params interface{}) (*Response, error) {
	return c.send("PUT", path, params)
}

func (c *Client) Patch(path string, params interface{}) (*Response, error) {
	return c.send("PATCH", path, params)
}

func (c *Client) Delete(path string, params interface{}) (*Response, error) {
	return c.send("DELETE", path, params)
}

func (c *Client) send(method string, path string, params interface{}) (*Response, error) {
	url := fmt.Sprintf("%s/%s/accounts/%s/%s", APIURL, APIVersion, c.account, path)
	var in bytes.Buffer

	if params != nil {
		switch {
		case method == http.MethodGet:
			values, err := query.Values(params)
			if err != nil {
				return nil, err
			}

			url += "?" + values.Encode()
		default:
			serialized, err := jsonapi.Marshal(params)
			if err != nil {
				return nil, err
			}

			in = *bytes.NewBuffer(serialized)
		}
	}

	req, err := http.NewRequest(method, url, &in)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+c.token)
	req.Header.Add("Content-Type", jsonapi.ContentType)
	req.Header.Add("Accept", jsonapi.ContentType)
	req.Header.Add("User-Agent", userAgent)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	out, err := ioutil.ReadAll(res.Body)
	res.Body.Close()

	if err != nil {
		return nil, err
	}

	response := &Response{
		Status:  res.StatusCode,
		Headers: res.Header,
		Body:    out,
	}

	if response.Status == http.StatusNoContent || len(out) == 0 {
		return response, nil
	}

	doc, err := jsonapi.Unmarshal(out, nil)
	if err != nil {
		return nil, err
	}

	if len(doc.Errors) > 0 {
		err := doc.Errors[0]

		switch {
		case err.Code == ErrorCodeFingerprintTaken:
			return response, ErrMachineAlreadyActivated
		case err.Code == ErrorCodeTokenInvalid:
			return response, ErrLicenseTokenInvalid
		case err.Code == ErrorCodeMachineDead:
			return response, ErrMachineDead
		case err.Code == ErrorCodeNotFound:
			return response, ErrNotFound
		default:
			return response, fmt.Errorf("an error occurred (id=%s status=%d response='%s')", res.Header.Get("x-request-id"), res.StatusCode, out)
		}
	}

	return response, nil
}
