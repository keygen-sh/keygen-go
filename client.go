package keygen

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"

	"github.com/pieoneers/jsonapi-go"
)

const (
	APIURL     = "https://api.keygen.sh"
	APIVersion = "v1"

	clientVersion = "1.0.0"
)

var (
	userAgent = "keygen/" + APIVersion + " sdk/" + clientVersion + " go/" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
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

type client struct {
	account string
	token   string
}

type Response struct {
	Headers http.Header
	Body    []byte
	Status  int
}

func (c *client) Post(path string, params interface{}) (*Response, error) {
	return c.send("POST", path, params)
}

func (c *client) Get(path string, params interface{}) (*Response, error) {
	return c.send("GET", path, params)
}

func (c *client) Put(path string, params interface{}) (*Response, error) {
	return c.send("PUT", path, params)
}

func (c *client) Patch(path string, params interface{}) (*Response, error) {
	return c.send("PATCH", path, params)
}

func (c *client) Delete(path string, params interface{}) (*Response, error) {
	return c.send("DELETE", path, params)
}

func (c *client) send(method string, path string, params interface{}) (*Response, error) {
	url := fmt.Sprintf("%s/%s/accounts/%s/%s", APIURL, APIVersion, c.account, path)
	var in bytes.Buffer

	if params != nil {
		var serialized []byte
		var err error

		switch {
		case method == "GET":
			// TODO(ezekg) Serialize into URL params for GET requests
		default:
			serialized, err = jsonapi.Marshal(params)
		}

		if err != nil {
			return nil, err
		}

		in = *bytes.NewBuffer(serialized)
	}

	req, err := http.NewRequest(method, url, &in)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+c.token)
	req.Header.Add("Content-Type", jsonapi.ContentType)
	req.Header.Add("Accept", jsonapi.ContentType)
	req.Header.Add("User-Agent", userAgent)

	cli := new(http.Client)
	res, err := cli.Do(req)
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
		switch {
		case doc.Errors[0].Code == ErrorCodeFingerprintTaken:
			return response, ErrMachineAlreadyActivated
		case doc.Errors[0].Code == ErrorCodeTokenInvalid:
			return response, ErrLicenseTokenInvalid
		case doc.Errors[0].Code == ErrorCodeMachineDead:
			return response, ErrMachineDead
		case doc.Errors[0].Code == ErrorCodeNotFound:
			return response, ErrNotFound
		default:
			return response, fmt.Errorf("an error occurred (id=%s status=%d response='%s')", res.Header.Get("x-request-id"), res.StatusCode, out)
		}
	}

	return response, nil
}
