package sreq_test

import (
	"net/http"
	"testing"

	"github.com/winterssy/sreq"
)

func TestGet(t *testing.T) {
	resp := sreq.Get("http://httpbin.org/get").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestHead(t *testing.T) {
	resp := sreq.Head("http://httpbin.org").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestPost(t *testing.T) {
	resp := sreq.Post("http://httpbin.org/post").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestPut(t *testing.T) {
	resp := sreq.Put("http://httpbin.org/put").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestPatch(t *testing.T) {
	resp := sreq.Patch("http://httpbin.org/patch").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestDelete(t *testing.T) {
	resp := sreq.Delete("http://httpbin.org/delete").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestOptions(t *testing.T) {
	resp := sreq.Options("http://httpbin.org").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestParams(t *testing.T) {
	var data struct {
		Args map[string]string `json:"args"`
	}
	err := sreq.Get("http://httpbin.org/get").
		Params(
			sreq.Value{
				"key1": "value1",
				"key2": "value2",
			}).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.Args["key1"] != "value1" || data.Args["key2"] != "value2" {
		t.Error("Set params failed")
	}
}

func TestForm(t *testing.T) {
	var data struct {
		Form map[string]string `json:"form"`
	}
	err := sreq.Post("http://httpbin.org/post").
		Form(
			sreq.Value{
				"key1": "value1",
				"key2": "value2",
			}).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.Form["key1"] != "value1" || data.Form["key2"] != "value2" {
		t.Error("Send form failed")
	}
}

func TestJSON(t *testing.T) {
	var data struct {
		JSON struct {
			Msg string `json:"msg"`
			Num int    `json:"num"`
		} `json:"json"`
	}
	err := sreq.Post("http://httpbin.org/post").
		JSON(
			sreq.Data{
				"msg": "hello world",
				"num": 2019,
			}).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.JSON.Msg != "hello world" || data.JSON.Num != 2019 {
		t.Error("Send json failed")
	}
}

func TestHeaders(t *testing.T) {
	var data struct {
		Headers map[string]string `json:"headers"`
	}
	err := sreq.Get("http://httpbin.org/get").
		Headers(
			sreq.Value{
				"Origin":  "http://httpbin.org",
				"Referer": "http://httpbin.org",
			}).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.Headers["Origin"] != "http://httpbin.org" || data.Headers["Referer"] != "http://httpbin.org" {
		t.Error("Set headers failed")
	}
}

func TestCookies(t *testing.T) {
	var data struct {
		Cookies map[string]string `json:"cookies"`
	}
	err := sreq.Get("http://httpbin.org/cookies/set").
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
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.Cookies["name1"] != "value1" || data.Cookies["name2"] != "value2" {
		t.Error("Set cookies failed")
	}
}

// TODO: This test case usually goes wrong if runs "go test -v ." for a batch of tests.
//  It may work with "go test -v -p=1 .", need to find out the reason.
// func TestFiles(t *testing.T) {
// 	var data struct {
// 		Files map[string]string `json:"files"`
// 	}
// 	err := grequests.New().Post("http://httpbin.org/post").
// 		Files(
// 			&grequests.File{
// 				FieldName: "testfile1",
// 				FileName:  "testfile1.txt",
// 				FilePath:  "./testdata/testfile1.txt",
// 			},
// 			&grequests.File{
// 				FieldName: "testfile2",
// 				FileName:  "testfile2.txt",
// 				FilePath:  "./testdata/testfile2.txt",
// 			},
// 		).
// 		Send().
// 		EnsureStatusOk().
// 		JSON(&data)
// 	if err != nil {
// 		t.Error(err)
// 	}
//
// 	if data.Files["testfile1"] == "" || data.Files["testfile2"] == "" {
// 		t.Error("Send files failed")
// 	}
// }

func TestBasicAuth(t *testing.T) {
	var data struct {
		Authenticated bool   `json:"authenticated"`
		User          string `json:"user"`
	}
	err := sreq.Get("http://httpbin.org/basic-auth/admin/pass").
		BasicAuth("admin", "pass").
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if !data.Authenticated || data.User != "admin" {
		t.Error("Set basic authentication failed")
	}
}

func TestBearerToken(t *testing.T) {
	var data struct {
		Authenticated bool   `json:"authenticated"`
		Token         string `json:"token"`
	}
	err := sreq.Get("http://httpbin.org/bearer").
		BearerToken("sreq").
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if !data.Authenticated || data.Token != "sreq" {
		t.Error("Set bearer token failed")
	}
}
