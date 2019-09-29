# sreq
A simple and user-friendly HTTP request library for Go, "s" means simple.

[![Build Status](https://travis-ci.org/winterssy/sreq.svg?branch=master)](https://travis-ci.org/winterssy/sreq) [![Go Report Card](https://goreportcard.com/badge/github.com/winterssy/sreq)](https://goreportcard.com/report/github.com/winterssy/sreq) [![GoDoc](https://godoc.org/github.com/winterssy/sreq?status.svg)](https://godoc.org/github.com/winterssy/sreq) [![License](https://img.shields.io/github/license/winterssy/sreq.svg)](LICENSE)

## Features

- GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, etc.
- Easy set query params, headers and cookies.
- Easy send form, JSON or files payload.
- Easy set basic authentication or bearer token.
- Easy customize root certificate authorities and client certificates.
- Easy set proxy.
- Automatic cookies management.
- Customize HTTP client, transport, redirect policy, cookie jar and timeout.
- Easy set context.
- Easy decode responses, raw data, text representation and unmarshal the JSON-encoded data.
- Concurrent safe.

## Install

```sh
go get -u github.com/winterssy/sreq
```

## Usage

```go
import "github.com/winterssy/sreq"
```

## Examples

- [Set Params](#Set-Params)
- [Set Headers](#Set-Headers)
- [Set Cookies](#Set-Cookies)
- [Set Form Payload](#Set-Form-Payload)
- [Set JSON Payload](#Set-JSON-Payload)
- [Set Files Payload](#Set-Files-Payload)
- [Set Basic Authentication](#Set-Basic-Authentication)
- [Set Bearer Token](#Set-Bearer-Token)
- [Customize HTTP Client](#Customize-HTTP-Client)
- [Set Proxy](#Set-Proxy)
- [Concurrent Safe](#Concurrent-Safe)

### Set Params

```go
data, err := sreq.
    Get("http://httpbin.org/get").
    Params(sreq.Value{
        "key1": "value1",
        "key2": "value2",
    }).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Headers

```go
data, err := sreq.
    Get("http://httpbin.org/get").
    Headers(sreq.Value{
        "Origin":  "http://httpbin.org",
        "Referer": "http://httpbin.org",
    }).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Cookies

```go
data, err := sreq.
    Get("http://httpbin.org/cookies/set").
    Cookies(
        &http.Cookie{
            Name:  "name1",
            Value: "value1",
        },
        &http.Cookie{
            Name:  "name2",
            Value: "value2",
        },
    ).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Form Payload

```go
data, err := sreq.
    Post("http://httpbin.org/post").
    Form(sreq.Value{
        "key1": "value1",
        "key2": "value2",
    }).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set JSON Payload

```go
data, err := sreq.
    Post("http://httpbin.org/post").
    JSON(sreq.Data{
        "msg": "hello world",
        "num": 2019,
    }).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Files Payload

```go
data, err := sreq.
    Post("http://httpbin.org/post").
    Files(
        &sreq.File{
            FieldName: "testimage1",
            FileName:  "testimage1.jpg",
            FilePath:  "./testdata/testimage1.jpg",
        },
        &sreq.File{
            FieldName: "testimage2",
            FileName:  "testimage2.jpg",
            FilePath:  "./testdata/testimage2.jpg",
        },
    ).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Basic Authentication

```go
data, err := sreq.
    Get("http://httpbin.org/basic-auth/admin/pass").
    BasicAuth("admin", "pass").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Bearer Token

```go
data, err := sreq.
    Get("http://httpbin.org/bearer").
    BearerToken("sreq").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Customize HTTP Client

```go
transport := &http.Transport{
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
redirectPolicy := func(req *http.Request, via []*http.Request) error {
    return http.ErrUseLastResponse
}
jar, _ := cookiejar.New(&cookiejar.Options{
    PublicSuffixList: publicsuffix.List,
})
timeout := 120 * time.Second

httpClient := &http.Client{
    Transport:     transport,
    CheckRedirect: redirectPolicy,
    Jar:           jar,
    Timeout:       timeout,
}
data, err := sreq.
    WithHTTPClient(httpClient).
    Get("http://httpbin.org/get").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Proxy

```go
data, err := sreq.
    WithProxy("http://127.0.0.1:1081").
    Get("http://httpbin.org/get").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Concurrent Safe

Use sreq across goroutines you must call `AcquireLock` for each request in the beginning, otherwise might cause data race. **Don't forget it!**

```go
const MaxWorker = 1000
wg := new(sync.WaitGroup)

for i := 0; i < MaxWorker; i += 1 {
    wg.Add(1)
    go func(i int) {
        defer wg.Done()

        params := sreq.Value{}
        params.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))

        data, err := sreq.
            AcquireLock().
            Get("http://httpbin.org/get").
            Params(params).
            Send().
            Text()
        if err != nil {
            return
        }

        fmt.Println(data)
    }(i)
}

wg.Wait()
```

## License

MIT.

## Thanks

- [xuanbo/requests](https://github.com/xuanbo/requests)
- [ddliu/go-httpclient](https://github.com/ddliu/go-httpclient)
- [go-resty/resty](https://github.com/go-resty/resty)
