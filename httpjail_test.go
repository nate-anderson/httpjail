package httpjail

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"
)

const testPort = ":8081"
const successRes = "SUCCESS"

// makeTestServer starts a test HTTP server with the provided jail and returns a close func
func makeTestServer(jail *Jail) func() {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, successRes)
	})

	withMiddleware := jail.Middleware(testHandler)

	srv := http.Server{
		Handler: withMiddleware,
		Addr:    testPort,
	}

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	ctx := context.Background()

	return func() {
		srv.Shutdown(ctx)
	}
}

func requestAllowed(t *testing.T) bool {
	testURL := fmt.Sprintf("http://localhost%s", testPort)
	res, err := http.Get(testURL)
	if err != nil {
		t.Logf("failed to reach test server at %s : %s", testURL, err.Error())
		t.FailNow()
	}

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Logf("failed to read response body : %s", err.Error())
		t.FailNow()
	}

	return string(bodyBytes) == successRes
}

func TestDefaultVisitorLogCountVisits(t *testing.T) {
	visitorLog := NewDefaultVisitorLog()

	testAddr := "0.0.0.0"

	since := time.Now()
	for i := 1; i <= 10; i++ {
		visitorLog.LogVisit(testAddr)

		visitCount := visitorLog.CountVisits(testAddr, since)
		if visitCount != i {
			t.Logf("incorrect visit count: got %d, expected %d", visitCount, i)
			t.Fail()
		}
	}

	after := time.Now()
	countAfter := visitorLog.CountVisits(testAddr, after)
	if countAfter != 0 {
		t.Logf("visitor log reported incorrect visitor count: got %d, expected %d", countAfter, 0)
		t.Fail()
	}
}

func TestMiddleware(t *testing.T) {
	// jail allows 1 request every 2 seconds
	windowSeconds := int64(5)
	allowedRequests := 5
	jail := NewBasicJail(windowSeconds, allowedRequests, false)

	stopServer := makeTestServer(jail)
	defer stopServer()

	// up to Nth request should be allowed
	for i := 0; i < allowedRequests; i++ {
		reached := requestAllowed(t)
		if !reached {
			t.Logf("server did not allow request %d", i)
			t.Fail()
		}
	}

	// N+1th request should be blocked
	reached := requestAllowed(t)
	if reached {
		t.Log("server did not block violating request")
		t.Fail()
	}

	// request should be allowed after waiting for end of window (no cooloff configured)
	time.Sleep(time.Duration(windowSeconds) * time.Second)

	reached = requestAllowed(t)
	if !reached {
		t.Log("server did not allow request after configured window")
		t.Fail()
	}
}

func TestProxiedMiddleware(t *testing.T) {
	jail := NewBasicJail(1, 1, false)
	jail.IsProxied()
	now := time.Now().Add(-time.Second)

	stopServer := makeTestServer(jail)
	defer stopServer()

	testURL := fmt.Sprintf("http://localhost%s", testPort)
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	testAddr := "1.2.3.4"

	req.Header.Add("X-Forwarded-For", testAddr)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if string(bodyBytes) != successRes {
		t.Fail()
	}

	count := jail.visitors.CountVisits(testAddr, now)
	if count != 1 {
		t.Logf("%#v", jail.visitors)
		t.Logf("Incorrect visit count: expected %d, got %d", 1, count)
		t.Fail()
	}

	log.Printf("%#v", jail.visitors)
}

func TestMiddlewareCooldown(t *testing.T) {
	cooloff := time.Duration(5) * time.Second
	requestWindow := time.Duration(5) * time.Second

	jail := &Jail{
		AllowedRequests: 1,
		NoRespond:       false,
		Cooloff:         cooloff,
		Window:          requestWindow,
		visitors:        NewDefaultVisitorLog(),
		Sentences:       make(map[string]time.Time),
	}

	stopServer := makeTestServer(jail)
	defer stopServer()

	// first request allowed
	reached := requestAllowed(t)
	if !reached {
		t.Log("first request denied")
		t.Fail()
	}

	// second request denied
	reached = requestAllowed(t)
	if reached {
		t.Log("request allowed, should be blocked")
		t.Fail()
	}

	// request allowed after cooloff
	time.Sleep(cooloff)
	reached = requestAllowed(t)
	if !reached {
		t.Log("cooloff did not expire")
		t.Fail()
	}

}
