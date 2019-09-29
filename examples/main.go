package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/winterssy/sreq"
	"golang.org/x/net/publicsuffix"
)

func main() {
	// setParams()
	// setHeaders()
	// setCookies()
	// setFormPayload()
	// setJSONPayload()
	// setFilesPayload()
	// setBasicAuth()
	// setBearerToken()
	// customizeHTTPClient()
	// setProxy()
	// concurrentSafe()
}

func setParams() {
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
}

func setHeaders() {
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
}

func setCookies() {
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
}

func setFormPayload() {
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
}

func setJSONPayload() {
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
}

func setFilesPayload() {
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
}

func setBasicAuth() {
	data, err := sreq.
		Get("http://httpbin.org/basic-auth/admin/pass").
		BasicAuth("admin", "pass").
		Send().
		Text()
	if err != nil {
		panic(err)
	}
	fmt.Println(data)
}

func setBearerToken() {
	data, err := sreq.
		Get("http://httpbin.org/bearer").
		BearerToken("grequests").
		Send().
		Text()
	if err != nil {
		panic(err)
	}
	fmt.Println(data)
}

func customizeHTTPClient() {
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
}

func setProxy() {
	data, err := sreq.
		WithProxy("http://127.0.0.1:1081").
		Get("http://httpbin.org/get").
		Send().
		Text()
	if err != nil {
		panic(err)
	}
	fmt.Println(data)
}

func concurrentSafe() {
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
}
