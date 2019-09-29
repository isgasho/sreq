package sreq

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	// Version of sreq.
	Version = "0.1"

	// ContentType is the same as "Content-Type".
	ContentType = "Content-Type"

	// TypeForm is the same as "application/x-www-form-urlencoded".
	TypeForm = "application/x-www-form-urlencoded"

	// TypeJSON is the same as "application/json".
	TypeJSON = "application/json"

	// MethodGet represents GET HTTP method
	MethodGet = "GET"

	// MethodHead represents HEAD HTTP method
	MethodHead = "HEAD"

	// MethodPost represents POST HTTP method
	MethodPost = "POST"

	// MethodPut represents PUT HTTP method
	MethodPut = "PUT"

	// MethodPatch represents PATCH HTTP method
	MethodPatch = "PATCH"

	// MethodDelete represents DELETE HTTP method
	MethodDelete = "DELETE"

	// MethodConnect represents CONNECT HTTP method
	MethodConnect = "CONNECT"

	// MethodOptions represents OPTIONS HTTP method
	MethodOptions = "OPTIONS"

	// MethodTrace represents TRACE HTTP method
	MethodTrace = "TRACE"
)

var std = New()

type (
	// Client defines a sreq client.
	Client struct {
		httpClient *http.Client
		method     string
		url        string
		params     Value
		form       Value
		json       Data
		host       string
		headers    Value
		cookies    []*http.Cookie
		files      []*File
		mux        *sync.Mutex
		withLock   bool
		ctx        context.Context
	}

	// Response wraps the original HTTP response and the potential error.
	Response struct {
		// R specifies the original HTTP response.
		R *http.Response

		// Err specifies the potential error.
		Err error
	}

	// Value is the same as map[string]string, used for params, headers, form, etc.
	Value map[string]string

	// Data is the same as map[string]interface{}, used for JSON payload.
	Data map[string]interface{}

	// File defines a multipart-data.
	File struct {
		// FieldName specifies the field name of the file you want to upload.
		FieldName string `json:"fieldname,omitempty"`

		// FileName specifies the file name of the file you want to upload.
		FileName string `json:"filename,omitempty"`

		// FilePath specifies the file path of the file you want to upload.
		FilePath string `json:"-"`
	}
)

// Get returns the value from a map by the given key.
func (v Value) Get(key string) string {
	return v[key]
}

// Set sets a kv pair into a map.
func (v Value) Set(key string, value string) {
	v[key] = value
}

// Del deletes the value related to the given key from a map.
func (v Value) Del(key string) {
	delete(v, key)
}

// Get returns the value from a map by the given key.
func (d Data) Get(key string) interface{} {
	return d[key]
}

// Set sets a kv pair into a map.
func (d Data) Set(key string, value interface{}) {
	d[key] = value
}

// Del deletes the value related to the given key from a map.
func (d Data) Del(key string) {
	delete(d, key)
}

// String returns the JSON-encoded text representation of a file.
func (f *File) String() string {
	b, err := json.Marshal(f)
	if err != nil {
		return "{}"
	}

	return string(b)
}

// New constructors and returns a new sreq client.
func New() *Client {
	c := &Client{
		httpClient: &http.Client{},
		params:     make(Value),
		form:       make(Value),
		json:       make(Data),
		headers:    make(Value),
		mux:        new(sync.Mutex),
	}

	jar, _ := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	c.httpClient.Jar = jar
	c.httpClient.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	c.httpClient.Timeout = 120 * time.Second

	c.headers.Set("User-Agent", "sreq "+Version)
	return c
}

// WithHTTPClient changes HTTP client of the default sreq client.
func WithHTTPClient(httpClient *http.Client) *Client {
	return std.WithHTTPClient(httpClient)
}

// WithHTTPClient sets HTTP client of c.
func (c *Client) WithHTTPClient(httpClient *http.Client) *Client {
	if httpClient != nil {
		c.httpClient = httpClient
	}
	return c
}

// WithTransport changes transport of the default sreq client.
func WithTransport(transport http.RoundTripper) *Client {
	return std.WithTransport(transport)
}

// WithTransport sets transport of c.
func (c *Client) WithTransport(transport http.RoundTripper) *Client {
	c.httpClient.Transport = transport
	return c
}

// WithRedirectPolicy changes redirection policy of the default sreq client.
func WithRedirectPolicy(policy func(req *http.Request, via []*http.Request) error) *Client {
	return std.WithRedirectPolicy(policy)
}

// WithRedirectPolicy sets redirection policy of c.
func (c *Client) WithRedirectPolicy(policy func(req *http.Request, via []*http.Request) error) *Client {
	c.httpClient.CheckRedirect = policy
	return c
}

// WithCookieJar changes cookie jar of the default sreq client.
func WithCookieJar(jar http.CookieJar) *Client {
	return std.WithCookieJar(jar)
}

// WithCookieJar sets cookie jar of c.
func (c *Client) WithCookieJar(jar http.CookieJar) *Client {
	c.httpClient.Jar = jar
	return c
}

// WithTimeout changes timeout of the default sreq client, zero means no timeout.
func WithTimeout(timeout time.Duration) *Client {
	return std.WithTimeout(timeout)
}

// WithTimeout sets timeout of c, zero means no timeout.
func (c *Client) WithTimeout(timeout time.Duration) *Client {
	c.httpClient.Timeout = timeout
	return c
}

// WithContext sets HTTP requests context of the default sreq client.
func WithContext(ctx context.Context) *Client {
	return std.WithContext(ctx)
}

// WithContext sets HTTP requests context of c.
func (c *Client) WithContext(ctx context.Context) *Client {
	c.ctx = ctx
	return c
}

// WithProxy sets proxy of the default sreq client from a url.
func WithProxy(url string) *Client {
	return std.WithProxy(url)
}

// WithProxy sets proxy of c from a url.
func (c *Client) WithProxy(url string) *Client {
	proxyURL, err := urlpkg.Parse(url)
	if err != nil {
		return c
	}

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}

	transport.Proxy = http.ProxyURL(proxyURL)
	return c
}

// WithClientCertificates appends client certificates of the default sreq client.
func WithClientCertificates(certs ...tls.Certificate) *Client {
	return std.WithClientCertificates(certs...)
}

// WithClientCertificates appends client certificates of c.
func (c *Client) WithClientCertificates(certs ...tls.Certificate) *Client {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}

	transport.TLSClientConfig.Certificates = append(transport.TLSClientConfig.Certificates, certs...)
	return c
}

// WithRootCA appends root certificate authorities of the default sreq client.
func WithRootCA(pemFilePath string) *Client {
	return std.WithRootCA(pemFilePath)
}

// WithRootCA appends root certificate authorities of c.
func (c *Client) WithRootCA(pemFilePath string) *Client {
	pemCert, err := ioutil.ReadFile(pemFilePath)
	if err != nil {
		return c
	}

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	if transport.TLSClientConfig.RootCAs == nil {
		transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	}

	transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(pemCert)
	return c
}

// DisableProxy lets the default sreq client not use proxy.
// sreq uses proxy from environment by default.
func DisableProxy() *Client {
	return std.DisableProxy()
}

// DisableProxy lets c not use proxy.
// sreq uses proxy from environment by default.
func (c *Client) DisableProxy() *Client {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}

	transport.Proxy = nil
	return c
}

// DisableSession lets the default sreq client not use cookie jar.
// Session is enabled by default, sreq use cookie jar to manage cookies automatically.
func DisableSession() *Client {
	return std.DisableSession()
}

// DisableSession lets c not use cookie jar.
// Session is enabled by default, sreq use cookie jar to manage cookies automatically.
func (c *Client) DisableSession() *Client {
	return c.WithCookieJar(nil)
}

// DisableRedirect lets the default sreq client not redirect HTTP requests.
// HTTP requests redirection is enabled by default.
func DisableRedirect() *Client {
	return std.DisableRedirect()
}

// DisableRedirect lets c not redirect HTTP requests.
// HTTP requests redirection is enabled by default.
func (c *Client) DisableRedirect() *Client {
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

// DisableKeepAlives disables HTTP keep-alives of the default sreq client.
// HTTP keep-alives is enabled by default.
func DisableKeepAlives() *Client {
	return std.DisableKeepAlives()
}

// DisableKeepAlives disables HTTP keep-alives of c.
// HTTP keep-alives is enabled by default.
func (c *Client) DisableKeepAlives() *Client {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}

	transport.DisableKeepAlives = true
	return c
}

// DisableVerify lets the default sreq client not verify
// the server's TLS certificate.
// TLS certificate verification is enabled by default.
func DisableVerify() *Client {
	return std.DisableVerify()
}

// DisableVerify lets c not verify the server's TLS certificate.
// TLS certificate verification is enabled by default.
func (c *Client) DisableVerify() *Client {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	return c
}

// AcquireLock locks the default sreq client.
// Use sreq across goroutines you must call AcquireLock for each request
// in the beginning, otherwise might cause data race. Don't forget it!
func AcquireLock() *Client {
	return std.AcquireLock()
}

// AcquireLock locks c.
// Use sreq across goroutines you must call AcquireLock for each request
// in the beginning, otherwise might cause data race. Don't forget it!
func (c *Client) AcquireLock() *Client {
	c.mux.Lock()
	c.withLock = true
	return c
}

// Get uses the default sreq client to make GET HTTP requests.
func Get(url string) *Client {
	return std.Get(url)
}

// Get uses c to make GET HTTP requests.
func (c *Client) Get(url string) *Client {
	c.method = MethodGet
	c.url = url
	return c
}

// Head uses the default sreq client to make HEAD HTTP requests.
func Head(url string) *Client {
	return std.Head(url)
}

// Head uses c to make HEAD HTTP requests.
func (c *Client) Head(url string) *Client {
	c.method = MethodHead
	c.url = url
	return c
}

// Post uses the default sreq client to make POST HTTP requests.
func Post(url string) *Client {
	return std.Post(url)
}

// Post uses c to make POST HTTP requests.
func (c *Client) Post(url string) *Client {
	c.method = MethodPost
	c.url = url
	return c
}

// Put uses the default sreq client to make PUT HTTP requests.
func Put(url string) *Client {
	return std.Put(url)
}

// Put uses c to make PUT HTTP requests.
func (c *Client) Put(url string) *Client {
	c.method = MethodPut
	c.url = url
	return c
}

// Patch uses the default sreq client to make PATCH HTTP requests.
func Patch(url string) *Client {
	return std.Patch(url)
}

// Patch uses c to make PATCH HTTP requests.
func (c *Client) Patch(url string) *Client {
	c.method = MethodPatch
	c.url = url
	return c
}

// Delete uses the default sreq client to make DELETE HTTP requests.
func Delete(url string) *Client {
	return std.Delete(url)
}

// Delete uses c to make DELETE HTTP requests.
func (c *Client) Delete(url string) *Client {
	c.method = MethodDelete
	c.url = url
	return c
}

// Connect uses the default sreq client to make CONNECT HTTP requests.
func Connect(url string) *Client {
	return std.Connect(url)
}

// Connect uses c to make CONNECT HTTP requests.
func (c *Client) Connect(url string) *Client {
	c.method = MethodConnect
	c.url = url
	return c
}

// Options uses the default sreq client to make OPTIONS HTTP requests.
func Options(url string) *Client {
	return std.Options(url)
}

// Options uses c to make OPTIONS HTTP requests.
func (c *Client) Options(url string) *Client {
	c.method = MethodOptions
	c.url = url
	return c
}

// Trace uses the default sreq client to make TRACE HTTP requests.
func Trace(url string) *Client {
	return std.Trace(url)
}

// Trace uses c to make TRACE HTTP requests.
func (c *Client) Trace(url string) *Client {
	c.method = MethodTrace
	c.url = url
	return c
}

// Reset resets state of the default sreq client.
func Reset() {
	std.Reset()
}

// Reset resets state of c so that other requests can acquire lock.
func (c *Client) Reset() {
	c.method = ""
	c.url = ""
	c.params = make(Value)
	c.form = make(Value)
	c.json = make(Data)
	c.headers = make(Value)
	c.cookies = nil
	c.files = nil

	if c.withLock {
		c.mux.Unlock()
	}
}

// Params sets query params of the default sreq client.
func Params(params Value) *Client {
	return std.Params(params)
}

// Params sets query params of c.
func (c *Client) Params(params Value) *Client {
	for k, v := range params {
		c.params.Set(k, v)
	}
	return c
}

// Form sets form payload of the default sreq client.
func Form(form Value) *Client {
	return std.Form(form)
}

// Form sets form payload of c.
func (c *Client) Form(form Value) *Client {
	c.headers.Set(ContentType, TypeForm)
	for k, v := range form {
		c.form.Set(k, v)
	}
	return c
}

// JSON sets JSON payload of the default sreq client.
func JSON(data Data) *Client {
	return std.JSON(data)
}

// JSON sets JSON payload of c.
func (c *Client) JSON(data Data) *Client {
	c.headers.Set(ContentType, TypeJSON)
	for k, v := range data {
		c.json.Set(k, v)
	}
	return c
}

// Files sets files payload of the default sreq client.
func Files(files ...*File) *Client {
	return std.Files(files...)
}

// Files sets files payload of c.
func (c *Client) Files(files ...*File) *Client {
	c.files = append(c.files, files...)
	return c
}

// Host specifies the host of the default sreq client on which the URL is sought.
func Host(host string) *Client {
	return std.Host(host)
}

// Host specifies the host of c on which the URL is sought.
func (c *Client) Host(host string) *Client {
	c.host = host
	return c
}

// Headers sets headers of the default sreq client.
func Headers(headers Value) *Client {
	return std.Headers(headers)
}

// Headers sets headers of c.
func (c *Client) Headers(headers Value) *Client {
	for k, v := range headers {
		c.headers.Set(k, v)
	}
	return c
}

// Cookies sets cookies of the default sreq client.
func Cookies(cookies ...*http.Cookie) *Client {
	return std.Cookies(cookies...)
}

// Cookies sets cookies of c.
func (c *Client) Cookies(cookies ...*http.Cookie) *Client {
	c.cookies = append(c.cookies, cookies...)
	return c
}

// BasicAuth sets basic authentication of the default sreq client.
func BasicAuth(username, password string) *Client {
	return std.BasicAuth(username, password)
}

// BasicAuth sets basic authentication of c.
func (c *Client) BasicAuth(username, password string) *Client {
	c.headers.Set("Authorization", "Basic "+basicAuth(username, password))
	return c
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// BearerToken sets bearer token of the default sreq client.
func BearerToken(token string) *Client {
	return std.BearerToken(token)
}

// BearerToken sets bearer token of c.
func (c *Client) BearerToken(token string) *Client {
	c.headers.Set("Authorization", "Bearer "+token)
	return c
}

// Send uses the default sreq client to send the HTTP request and returns its response.
func Send() *Response {
	return std.Send()
}

// Send uses c to send the HTTP request and returns its response.
func (c *Client) Send() *Response {
	resp := new(Response)
	if c.url == "" {
		resp.Err = errors.New("url not specified")
		c.Reset()
		return resp
	}
	if c.method == "" {
		resp.Err = errors.New("method not specified")
		c.Reset()
		return resp
	}

	var httpReq *http.Request
	var err error
	contentType := c.headers.Get(ContentType)
	if len(c.files) != 0 {
		httpReq, err = c.buildMultipartRequest()
	} else if strings.HasPrefix(contentType, TypeForm) {
		httpReq, err = c.buildFormRequest()
	} else if strings.HasPrefix(contentType, TypeJSON) {
		httpReq, err = c.buildJSONRequest()
	} else {
		httpReq, err = c.buildStdRequest()
	}
	if err != nil {
		resp.Err = err
		c.Reset()
		return resp
	}

	if c.ctx != nil {
		httpReq = httpReq.WithContext(c.ctx)
	}

	if len(c.params) != 0 {
		c.addParams(httpReq)
	}
	if len(c.headers) != 0 {
		c.addHeaders(httpReq)
	}
	if len(c.cookies) != 0 {
		c.addCookies(httpReq)
	}
	if c.host != "" {
		httpReq.Host = c.host
	}

	c.Reset()

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		resp.Err = err
		return resp
	}

	resp.R = httpResp
	return resp
}

func (c *Client) buildStdRequest() (*http.Request, error) {
	return http.NewRequest(c.method, c.url, nil)
}

func (c *Client) buildFormRequest() (*http.Request, error) {
	form := urlpkg.Values{}
	for k, v := range c.form {
		form.Set(k, v)
	}
	return http.NewRequest(c.method, c.url, strings.NewReader(form.Encode()))
}

func (c *Client) buildJSONRequest() (*http.Request, error) {
	b, err := json.Marshal(c.json)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(c.method, c.url, bytes.NewReader(b))
}

func (c *Client) buildMultipartRequest() (*http.Request, error) {
	r, w := io.Pipe()
	mw := multipart.NewWriter(w)
	go func() {
		defer w.Close()
		defer mw.Close()

		for i, v := range c.files {
			fieldName, fileName, filePath := v.FieldName, v.FileName, v.FilePath
			if fieldName == "" {
				fieldName = "file" + strconv.Itoa(i)
			}
			if fileName == "" {
				fileName = filepath.Base(filePath)
			}

			part, err := mw.CreateFormFile(fieldName, fileName)
			if err != nil {
				return
			}
			file, err := os.Open(filePath)
			if err != nil {
				return
			}

			_, err = io.Copy(part, file)
			if err != nil || file.Close() != nil {
				return
			}
		}
	}()

	c.headers.Set(ContentType, mw.FormDataContentType())
	return http.NewRequest(c.method, c.url, r)
}

func (c *Client) addParams(httpReq *http.Request) {
	query := httpReq.URL.Query()
	for k, v := range c.params {
		query.Set(k, v)
	}
	httpReq.URL.RawQuery = query.Encode()
}

func (c *Client) addHeaders(httpReq *http.Request) {
	for k, v := range c.headers {
		httpReq.Header.Set(k, v)
	}
}

func (c *Client) addCookies(httpReq *http.Request) {
	for _, c := range c.cookies {
		httpReq.AddCookie(c)
	}
}

// Resolve resolves r and returns its original HTTP response.
func (r *Response) Resolve() (*http.Response, error) {
	return r.R, r.Err
}

// Raw decodes the HTTP response body of r and returns its raw data.
func (r *Response) Raw() ([]byte, error) {
	if r.Err != nil {
		return nil, r.Err
	}
	defer r.R.Body.Close()

	b, err := ioutil.ReadAll(r.R.Body)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Text decodes the HTTP response body of r and returns the text representation of its raw data.
func (r *Response) Text() (string, error) {
	b, err := r.Raw()
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// JSON decodes the HTTP response body of r and unmarshals its JSON-encoded data into v.
func (r *Response) JSON(v interface{}) error {
	// b, err := r.Raw()
	// if err != nil {
	// 	return err
	// }
	//
	// return json.Unmarshal(b, v)
	return json.NewDecoder(r.R.Body).Decode(v)
}

// EnsureStatusOk ensures the HTTP response's status code of r must be 200.
func (r *Response) EnsureStatusOk() *Response {
	if r.Err != nil {
		return r
	}
	if r.R.StatusCode != http.StatusOK {
		r.Err = fmt.Errorf("status code 200 expected but got: %d", r.R.StatusCode)
	}
	return r
}

// EnsureStatus2xx ensures the HTTP response's status code of r must be 2xx.
func (r *Response) EnsureStatus2xx() *Response {
	if r.Err != nil {
		return r
	}
	if r.R.StatusCode/100 != 2 {
		r.Err = fmt.Errorf("status code 2xx expected but got: %d", r.R.StatusCode)
	}
	return r
}
