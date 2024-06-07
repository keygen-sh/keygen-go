package keygen

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/keygen-sh/jsonapi-go"
)

var (
	userAgent = "keygen/" + APIVersion + " sdk/" + SDKVersion + " go/" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH

	// mutex is used to sychronize access to the HTTP client.
	mutex = &sync.Mutex{}
)

type Response struct {
	Request  *http.Request
	ID       string
	Headers  http.Header
	Document *jsonapi.Document
	Size     int
	Body     []byte
	Status   int
}

// tldr truncates the response body if it's too large, just in case this is some
// sort of unexpected response format. We should always be responding with JSON,
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

// ClientOptions stores config options used in API requests.
type ClientOptions struct {
	Account     string
	Environment string
	LicenseKey  string
	Token       string
	PublicKey   string
	UserAgent   string
	APIVersion  string
	APIPrefix   string
	APIURL      string
}

// Client represents the internal HTTP client and config used for API requests.
type Client struct {
	HTTPClient *http.Client
	ClientOptions

	mutex *sync.Mutex
}

// NewClient creates a new Client with default settings.
func NewClient() *Client {
	client := &Client{
		HTTPClient,
		ClientOptions{
			Account:     Account,
			Environment: Environment,
			LicenseKey:  LicenseKey,
			Token:       Token,
			PublicKey:   PublicKey,
			UserAgent:   UserAgent,
			APIPrefix:   APIPrefix,
			APIVersion:  APIVersion,
			APIURL:      APIURL,
		},
		mutex,
	}

	return client
}

// NewClientWithOptions creates a new client with custom settings.
func NewClientWithOptions(options *ClientOptions) *Client {
	client := &Client{
		HTTPClient,
		ClientOptions{
			Account:     options.Account,
			Environment: options.Environment,
			LicenseKey:  options.LicenseKey,
			Token:       options.Token,
			PublicKey:   options.PublicKey,
			UserAgent:   options.UserAgent,
			APIPrefix:   options.APIPrefix,
			APIVersion:  options.APIVersion,
			APIURL:      options.APIURL,
		},
		mutex,
	}

	return client
}

// Post is a convenience helper for performing POST requests.
func (c *Client) Post(path string, params interface{}, model interface{}) (*Response, error) {
	req, err := c.new(http.MethodPost, path, params)
	if err != nil {
		return nil, err
	}

	return c.send(req, model)
}

// Get is a convenience helper for performing GET requests.
func (c *Client) Get(path string, params interface{}, model interface{}) (*Response, error) {
	req, err := c.new(http.MethodGet, path, params)
	if err != nil {
		return nil, err
	}

	return c.send(req, model)
}

// Put is a convenience helper for performing PUT requests.
func (c *Client) Put(path string, params interface{}, model interface{}) (*Response, error) {
	req, err := c.new(http.MethodPut, path, params)
	if err != nil {
		return nil, err
	}

	return c.send(req, model)
}

// Patch is a convenience helper for performing PATCH requests.
func (c *Client) Patch(path string, params interface{}, model interface{}) (*Response, error) {
	req, err := c.new(http.MethodPatch, path, params)
	if err != nil {
		return nil, err
	}

	return c.send(req, model)
}

// Delete is a convenience helper for performing DELETE requests.
func (c *Client) Delete(path string, params interface{}, model interface{}) (*Response, error) {
	req, err := c.new(http.MethodDelete, path, params)
	if err != nil {
		return nil, err
	}

	return c.send(req, model)
}

func (c *Client) new(method string, path string, params interface{}) (*http.Request, error) {
	var url string

	if c.APIVersion == "" {
		c.APIVersion = APIVersion
	}

	if c.APIPrefix == "" {
		c.APIPrefix = APIPrefix
	}

	if c.APIURL == "" {
		c.APIURL = APIURL
	}

	// Local vars so we don't mutate the client
	account := c.Account
	prefix := c.APIPrefix
	host := c.APIURL

	// Add scheme if not present (e.g. with self-hosted KEYGEN_HOST env var via the CLI)
	if !strings.HasPrefix(host, "https://") && !strings.HasPrefix(host, "http://") {
		host = "https://" + host
	}

	// Support for custom domains
	if host == "https://api.keygen.sh" {
		url = fmt.Sprintf("%s/%s/accounts/%s/%s", host, prefix, account, path)
	} else {
		url = fmt.Sprintf("%s/%s/%s", host, prefix, path)
	}

	ua := strings.Join([]string{userAgent, c.UserAgent}, " ")
	var in bytes.Buffer

	if params != nil {
		if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
			serialized, err := jsonapi.Marshal(params)
			if err != nil {
				return nil, err
			}

			in = *bytes.NewBuffer(serialized)
		}

		if opts, ok := params.(CheckoutOptions); ok {
			values, err := query.Values(opts)
			if err != nil {
				return nil, err
			}

			if enc := values.Encode(); enc != "" {
				url += "?" + values.Encode()
			}
		}

		if qs, ok := params.(querystring); ok {
			values, err := query.Values(qs)
			if err != nil {
				return nil, err
			}

			if enc := values.Encode(); enc != "" {
				url += "?" + values.Encode()
			}
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

	if c.Environment != "" {
		req.Header.Add("Keygen-Environment", c.Environment)
	}

	req.Header.Add("Keygen-Version", c.APIVersion)

	if in.Len() > 0 {
		req.Header.Add("Content-Type", jsonapi.ContentType)
	}

	req.Header.Add("Accept", jsonapi.ContentType)
	req.Header.Add("User-Agent", ua)

	return req, nil
}

func (c *Client) send(req *http.Request, model interface{}) (*Response, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.HTTPClient.CheckRedirect = c.checkRedirect

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		Logger.Errorf("Error performing request: method=%s url=%s err=%v", req.Method, req.URL, err)

		return nil, err
	}

	requestID := res.Header.Get("x-request-id")
	out, err := io.ReadAll(res.Body)
	res.Body.Close()

	if err != nil {
		Logger.Errorf("Error reading response body: id=%s status=%d err=%v", requestID, res.StatusCode, err)

		return nil, err
	}

	response := &Response{
		Request: res.Request,
		ID:      requestID,
		Status:  res.StatusCode,
		Headers: res.Header,
		Size:    len(out),
		Body:    out,
	}

	Logger.Infof("Response: id=%s status=%d size=%d", response.ID, response.Status, response.Size)
	if response.Size > 0 {
		Logger.Debugf("         body=%s", response.Body)
	}

	// Handle certain error statuses before we check signature
	switch {
	case response.Status == http.StatusTooManyRequests:
		err := &Error{response, "", "", "TOO_MANY_REQUESTS", ""}
		window := response.Headers.Get("X-RateLimit-Window")
		var retryAfter, count, limit, remaining int
		var reset time.Time

		if i, e := strconv.Atoi(response.Headers.Get("Retry-After")); e == nil {
			retryAfter = i
		}

		if i, e := strconv.Atoi(response.Headers.Get("X-RateLimit-Count")); e == nil {
			count = i
		}

		if i, e := strconv.Atoi(response.Headers.Get("X-RateLimit-Limit")); e == nil {
			limit = i
		}

		if i, e := strconv.Atoi(response.Headers.Get("X-RateLimit-Remaining")); e == nil {
			remaining = i
		}

		if i, e := strconv.ParseInt(response.Headers.Get("X-RateLimit-Reset"), 10, 64); e == nil {
			reset = time.Unix(i, 0)
		}

		return response, &RateLimitError{
			Window:     window,
			Count:      count,
			Limit:      limit,
			Remaining:  remaining,
			Reset:      reset,
			RetryAfter: retryAfter,
			Err:        err,
		}
	case response.Status >= http.StatusInternalServerError:
		Logger.Errorf("An unexpected API error occurred: id=%s status=%d size=%d body=%s", response.ID, response.Status, response.Size, response.tldr())

		return response, fmt.Errorf("an error occurred: id=%s status=%d size=%d body=%s", response.ID, response.Status, response.Size, response.tldr())
	}

	if c.PublicKey != "" {
		verifier := &verifier{c.PublicKey}

		if err := verifier.VerifyResponse(response); err != nil {
			Logger.Errorf("Error verifying response signature: id=%s status=%d size=%d body=%s err=%v", response.ID, response.Status, response.Size, response.tldr(), err)

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

	if len(doc.Errors) > 0 {
		err := &Error{response, doc.Errors[0].Title, doc.Errors[0].Detail, doc.Errors[0].Code, doc.Errors[0].Source.Pointer}

		if response.Status == http.StatusForbidden {
			code := ErrorCode(err.Code)

			// Handle certain license auth error codes so that we emit helpful errors
			switch {
			case code == ErrorCodeTokenNotAllowed:
				return response, ErrTokenNotAllowed
			case code == ErrorCodeTokenFormatInvalid:
				return response, ErrTokenFormatInvalid
			case code == ErrorCodeTokenInvalid:
				return response, ErrTokenInvalid
			case code == ErrorCodeTokenExpired:
				return response, ErrTokenExpired
			case code == ErrorCodeLicenseNotAllowed:
				return response, ErrLicenseNotAllowed
			case code == ErrorCodeLicenseSuspended:
				return response, ErrLicenseSuspended
			case code == ErrorCodeLicenseExpired:
				return response, ErrLicenseExpired
			default:
				return response, &NotAuthorizedError{err}
			}
		}

		// TODO(ezekg) Handle additional error codes
		code := ErrorCode(doc.Errors[0].Code)

		switch {
		case code == ErrorCodeEnvironmentNotSupported || code == ErrorCodeEnvironmentInvalid:
			return response, &EnvironmentError{err}
		case code == ErrorCodeMachineHeartbeatDead || code == ErrorCodeProcessHeartbeatDead:
			return response, ErrHeartbeatDead
		case code == ErrorCodeFingerprintTaken:
			return response, ErrMachineAlreadyActivated
		case code == ErrorCodeMachineLimitExceeded:
			return response, ErrMachineLimitExceeded
		case code == ErrorCodeProcessLimitExceeded:
			return response, ErrProcessLimitExceeded
		case code == ErrorCodeComponentFingerprintConflict:
			return response, ErrComponentConflict
		case code == ErrorCodeComponentFingerprintTaken:
			return response, ErrComponentAlreadyActivated
		case code == ErrorCodeTokenInvalid:
			return response, &LicenseTokenError{err}
		case code == ErrorCodeLicenseInvalid:
			return response, &LicenseKeyError{err}
		case code == ErrorCodeNotFound:
			return response, &NotFoundError{err}
		default:
			return response, err
		}
	}

	return response, nil
}

// We don't want to automatically follow redirects
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}
