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

var (
	userAgent = "keygen/" + APIVersion + " sdk/" + SDKVersion + " go/" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	client    = &http.Client{
		// We don't want to automatically follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

type ErrorCode string

const (
	ErrorCodeTokenInvalid         ErrorCode = "TOKEN_INVALID"
	ErrorCodeFingerprintTaken     ErrorCode = "FINGERPRINT_TAKEN"
	ErrorCodeMachineLimitExceeded ErrorCode = "MACHINE_LIMIT_EXCEEDED"
	ErrorCodeMachineHeartbeatDead ErrorCode = "MACHINE_HEARTBEAT_DEAD"
	ErrorCodeNotFound             ErrorCode = "NOT_FOUND"
)

var (
	ErrLicenseTokenInvalid     = errors.New("authentication token is invalid")
	ErrMachineAlreadyActivated = errors.New("machine is already activated")
	ErrMachineLimitExceeded    = errors.New("machine limit has been exceeded")
	ErrMachineHeartbeatDead    = errors.New("machine heartbeat is dead")
	ErrNotAuthorized           = errors.New("token is not authorized to perform the request")
	ErrNotFound                = errors.New("resource does not exist")
)

type Client struct {
	Account string
	Token   string
}

type Response struct {
	Method   string
	URL      string
	Headers  http.Header
	Document *jsonapi.Document
	Body     []byte
	Status   int
}

func (c *Client) Post(path string, params interface{}, model interface{}) (*Response, error) {
	return c.send("POST", path, params, model)
}

func (c *Client) Get(path string, params interface{}, model interface{}) (*Response, error) {
	return c.send("GET", path, params, model)
}

func (c *Client) Put(path string, params interface{}, model interface{}) (*Response, error) {
	return c.send("PUT", path, params, model)
}

func (c *Client) Patch(path string, params interface{}, model interface{}) (*Response, error) {
	return c.send("PATCH", path, params, model)
}

func (c *Client) Delete(path string, params interface{}, model interface{}) (*Response, error) {
	return c.send("DELETE", path, params, model)
}

func (c *Client) send(method string, path string, params interface{}, model interface{}) (*Response, error) {
	url := fmt.Sprintf("%s/%s/accounts/%s/%s", APIURL, APIVersion, c.Account, path)
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

	req.Header.Add("Authorization", "Bearer "+c.Token)
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
		Method:  method,
		URL:     url,
		Status:  res.StatusCode,
		Headers: res.Header,
		Body:    out,
	}

	if response.Status < http.StatusInternalServerError && PublicKey != "" {
		if err := verifyResponseSignature(response); err != nil {
			return response, err
		}
	}

	if response.Status == http.StatusNoContent || len(out) == 0 {
		return response, nil
	}

	doc, err := jsonapi.Unmarshal(out, model)
	if err != nil {
		return response, err
	}

	response.Document = doc

	if response.Status == http.StatusForbidden {
		return response, ErrNotAuthorized
	}

	if len(doc.Errors) > 0 {
		code := ErrorCode(doc.Errors[0].Code)

		// TODO(ezekg) Handle additional error codes
		switch {
		case code == ErrorCodeFingerprintTaken:
			return response, ErrMachineAlreadyActivated
		case code == ErrorCodeMachineLimitExceeded:
			return response, ErrMachineLimitExceeded
		case code == ErrorCodeTokenInvalid:
			return response, ErrLicenseTokenInvalid
		case code == ErrorCodeMachineHeartbeatDead:
			return response, ErrMachineHeartbeatDead
		case code == ErrorCodeNotFound:
			return response, ErrNotFound
		default:
			return response, fmt.Errorf("an error occurred: id=%s status=%d response='%s'", res.Header.Get("x-request-id"), res.StatusCode, out)
		}
	}

	return response, nil
}
