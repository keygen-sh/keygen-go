package keygen

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"

	"github.com/google/go-querystring/query"
	"github.com/keygen-sh/jsonapi-go"
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
	ErrorCodeLicenseInvalid       ErrorCode = "LICENSE_INVALID"
	ErrorCodeFingerprintTaken     ErrorCode = "FINGERPRINT_TAKEN"
	ErrorCodeMachineLimitExceeded ErrorCode = "MACHINE_LIMIT_EXCEEDED"
	ErrorCodeMachineHeartbeatDead ErrorCode = "MACHINE_HEARTBEAT_DEAD"
	ErrorCodeNotFound             ErrorCode = "NOT_FOUND"
)

var (
	ErrLicenseTokenInvalid      = errors.New("token authentication is invalid")
	ErrLicenseKeyInvalid        = errors.New("license key authentication is invalid")
	ErrMachineAlreadyActivated  = errors.New("machine is already activated")
	ErrMachineLimitExceeded     = errors.New("machine limit has been exceeded")
	ErrMachineHeartbeatRequired = errors.New("machine heartbeat is required")
	ErrMachineHeartbeatDead     = errors.New("machine heartbeat is dead")
	ErrNotAuthorized            = errors.New("token is not authorized to perform the request")
	ErrNotFound                 = errors.New("resource does not exist")
)

type Response struct {
	ID       string
	Method   string
	URL      string
	Headers  http.Header
	Document *jsonapi.Document
	Size     int
	Body     []byte
	Status   int
}

// Truncate the response body if it's too large, just in case this is some sort
// of unexpected response format. We should always be responding with JSON,
// regardless of any errors that occur, but this may be from infra.
func (r *Response) tldr() string {
	tldr := string(r.Body)
	if len(tldr) > 500 {
		tldr = tldr[0:500] + "..."
	}

	// Make sure a multi-line response ends up all on one line.
	tldr = strings.Replace(tldr, "\n", "\\n", -1)

	return tldr
}

type Client struct {
	Account    string
	LicenseKey string
	Token      string
	PublicKey  string
	UserAgent  string
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
	ua := strings.Join([]string{userAgent, c.UserAgent}, " ")
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

	Logger.Infof("Request: method=%s url=%s size=%d", method, url, in.Len())
	if in.Len() > 0 {
		Logger.Debugf("        body=%s", in.Bytes())
	}

	req, err := http.NewRequest(method, url, &in)
	if err != nil {
		Logger.Errorf("Error building request: method=%s url=%s err=%v", method, url, err)

		return nil, err
	}

	switch {
	case c.LicenseKey != "":
		req.Header.Add("Authorization", "License "+c.LicenseKey)
	case c.Token != "":
		req.Header.Add("Authorization", "Bearer "+c.Token)
	}

	req.Header.Add("Content-Type", jsonapi.ContentType)
	req.Header.Add("Accept", jsonapi.ContentType)
	req.Header.Add("User-Agent", ua)

	res, err := client.Do(req)
	if err != nil {
		Logger.Errorf("Error performing request: method=%s url=%s err=%v", method, url, err)

		return nil, err
	}

	requestID := res.Header.Get("x-request-id")
	out, err := ioutil.ReadAll(res.Body)
	res.Body.Close()

	if err != nil {
		Logger.Errorf("Error reading response body: id=%s status=%d err=%v", requestID, res.StatusCode, err)

		return nil, err
	}

	response := &Response{
		ID:      requestID,
		Method:  method,
		URL:     url,
		Status:  res.StatusCode,
		Headers: res.Header,
		Size:    len(out),
		Body:    out,
	}

	Logger.Infof("Response: id=%s status=%d size=%d", response.ID, response.Status, response.Size)
	if response.Size > 0 {
		Logger.Debugf("         body=%s", response.Body)
	}

	if response.Status >= http.StatusInternalServerError {
		Logger.Errorf("An unexpected API error occurred: id=%s status=%d size=%d body=%s", response.ID, response.Status, response.Size, response.tldr())

		return response, fmt.Errorf("an error occurred: id=%s status=%d size=%d body=%s", response.ID, response.Status, response.Size, response.tldr())
	}

	if c.PublicKey != "" {
		if err := verifyResponseSignature(c.PublicKey, response); err != nil {
			Logger.Errorf("Error verifying response signature: id=%s status=%d size=%d body=%s err=%v", response.ID, response.Status, response.tldr(), err)

			return response, err
		}
	}

	if response.Status == http.StatusNoContent || response.Size == 0 {
		return response, nil
	}

	doc, err := jsonapi.Unmarshal(response.Body, model)
	if err != nil {
		Logger.Errorf("Error parsing response JSON: id=%s status=%d size=%d body=%s err=%v", response.ID, response.Status, response.Size, response.tldr(), err)

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
		case code == ErrorCodeLicenseInvalid:
			return response, ErrLicenseKeyInvalid
		case code == ErrorCodeMachineHeartbeatDead:
			return response, ErrMachineHeartbeatDead
		case code == ErrorCodeNotFound:
			return response, ErrNotFound
		default:
			return response, fmt.Errorf("an error occurred: id=%s status=%d size=%d body=%s", response.ID, response.Status, response.Size, response.Body)
		}
	}

	return response, nil
}
