// The MIT License (MIT)
//
// Copyright (c) 2016 Bo-Yi Wu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// This file may have been modified by CloudWeGo authors. All CloudWeGo
// Modifications are Copyright 2022 CloudWeGo Authors.

package secure

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/cloudwego/hertz/pkg/route"
)

const (
	testResponse = "bar"
)

func newPolicyForTest(opts []Option) *policy {
	policy := &policy{}
	policy.fixedHeaders = &protocol.ResponseHeader{}
	policy.config.Apply(opts)
	// Frame Options header.
	if len(policy.config.customFrameOptionsValue) > 0 {
		policy.addHeader("X-Frame-Options", policy.config.customFrameOptionsValue)
	} else if policy.config.frameDeny {
		policy.addHeader("X-Frame-Options", "DENY")
	}

	// Content Type Options header.
	if policy.config.contentTypeNosniff {
		policy.addHeader("X-Content-Type-Options", "nosniff")
	}

	// XSS Protection header.
	if policy.config.browserXssFilter {
		policy.addHeader("X-Xss-Protection", "1; mode=block")
	}

	// Content Security Policy header.
	if len(policy.config.contentSecurityPolicy) > 0 {
		policy.addHeader("Content-Security-Policy", policy.config.contentSecurityPolicy)
	}

	if len(policy.config.referrerPolicy) > 0 {
		policy.addHeader("Referrer-Policy", policy.config.referrerPolicy)
	}

	// Strict Transport Security header.
	if policy.config.stsSeconds != 0 {
		stsSub := ""
		if policy.config.stsIncludeSubdomains {
			stsSub = "; includeSubdomains"
		}

		policy.addHeader(
			"Strict-Transport-Security",
			fmt.Sprintf("max-age=%d%s", policy.config.stsSeconds, stsSub))
	}

	// X-Download-Options header.
	if policy.config.ieNoOpen {
		policy.addHeader("X-Download-Options", "noopen")
	}

	// featurePolicy header.
	if len(policy.config.featurePolicy) > 0 {
		policy.addHeader("Feature-Policy", policy.config.featurePolicy)
	}
	return policy
}

func newServer(options ...Option) *route.Engine {
	opts := config.NewOptions([]config.Option{})
	engine := route.NewEngine(opts)
	engine.Use(func(ctx context.Context, c *app.RequestContext) {
		policy := newPolicyForTest(options)
		if !policy.applyToContext(ctx, c) {
			return
		}
		c.Next(ctx)
	})
	engine.GET("/foo", func(_ context.Context, c *app.RequestContext) {
		c.String(200, testResponse)
	})
	return engine
}

func TestNoConfig(t *testing.T) {
	engine := newServer()
	w := ut.PerformRequest(engine, "GET", "http://example.com/foo", nil)
	result := w.Result()
	assert.DeepEqual(t, 200, result.StatusCode())
	assert.DeepEqual(t, "bar", string(result.Body()))
}

func TestNoAllowHosts(t *testing.T) {
	engine := newServer(WithAllowedHosts([]string{}))
	result := performRequest(engine, "http://www.example.com/foo")
	assert.DeepEqual(t, http.StatusOK, result.StatusCode())
	assert.DeepEqual(t, "bar", string(result.Body()))
}

func TestGoodSingleAllowHosts(t *testing.T) {
	router := newServer(WithAllowedHosts([]string{"www.example.com"}))

	w := performRequest(router, "http://www.example.com/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "bar", string(w.Body()))
}

func TestGoodMulitipleAllowHosts(t *testing.T) {
	router := newServer(WithAllowedHosts([]string{"www.example.com", "sub.example.com"}))

	w := performRequest(router, "http://sub.example.com/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "bar", string(w.Body()))
}

func TestBadSingleAllowHosts(t *testing.T) {
	router := newServer(WithAllowedHosts([]string{"sub.example.com"}))

	w := performRequest(router, "http://www.example.com/foo")

	assert.DeepEqual(t, http.StatusForbidden, w.StatusCode())
}

func TestGoodMultipleAllowHosts(t *testing.T) {
	router := newServer(WithAllowedHosts([]string{"www.example.com", "sub.example.com"}))

	w := performRequest(router, "http://sub.example.com/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "bar", string(w.Body()))
}

func TestBadMultipleAllowHosts(t *testing.T) {
	router := newServer(WithAllowedHosts([]string{"www.example.com", "sub.example.com"}))

	w := performRequest(router, "http://www3.example.com/foo")

	assert.DeepEqual(t, http.StatusForbidden, w.StatusCode())
}

func TestAllowHostsInDevMode(t *testing.T) {
	router := newServer(
		WithAllowedHosts([]string{"www.example.com", "sub.example.com"}),
		WithIsDevelopment(true),
	)

	w := performRequest(router, "http://www3.example.com/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
}

func TestBadHostHandler(t *testing.T) {
	badHandler := func(_ context.Context, c *app.RequestContext) {
		c.String(http.StatusInternalServerError, "BadHost")
		c.Abort()
	}

	router := newServer(
		WithAllowedHosts([]string{"www.example.com", "sub.example.com"}),
		WithBadHostHandler(badHandler),
	)
	w := performRequest(router, "http://www3.example.com/foo")
	assert.DeepEqual(t, http.StatusInternalServerError, w.StatusCode())
	assert.DeepEqual(t, "BadHost", string(w.Body()))
}

func TestSSL(t *testing.T) {
	router := newServer(WithSSLRedirect(true))

	w := performRequest(router, "https://www.example.com/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "bar", string(w.Body()))
}

func TestSSLInDevMode(t *testing.T) {
	router := newServer(
		WithSSLRedirect(true),
		WithIsDevelopment(true),
	)
	w := performRequest(router, "http://www.example.com/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "bar", string(w.Body()))
}

func TestBasicSSL(t *testing.T) {
	router := newServer(WithSSLRedirect(true))

	w := performRequest(router, "http://www.example.com/foo")

	assert.DeepEqual(t, http.StatusMovedPermanently, w.StatusCode())
	assert.DeepEqual(t, "https://www.example.com/foo", w.Header.Get("Location"))
}

func TestDontRedirectIPV4Hostnames(t *testing.T) {
	router := newServer(
		WithDontRedirectIPV4Hostnames(true),
		WithSSLRedirect(true),
	)

	w1 := performRequest(router, "http://www.example.com/foo")
	assert.DeepEqual(t, http.StatusMovedPermanently, w1.StatusCode())

	w2 := performRequest(router, "http://127.0.0.1/foo")
	assert.DeepEqual(t, http.StatusOK, w2.StatusCode())
}

func TestBasicSSLWithHost(t *testing.T) {
	router := newServer(
		WithSSLRedirect(true),
		WithSSLHost("secure.example.com"),
	)
	w := performRequest(router, "http://www.example.com/foo")

	assert.DeepEqual(t, http.StatusMovedPermanently, w.StatusCode())
	assert.DeepEqual(t, "https://secure.example.com/foo", w.Header.Get("Location"))
}

func TestBadProxySSL(t *testing.T) {
	var req protocol.Request
	req.Header.Add("X-Forwarded-Proto", "https")
	engine := newServer(WithSSLRedirect(true))
	w := ut.PerformRequest(engine, "GET", "http://www.example.com/foo", nil, ut.Header{
		Key:   "X-Forwarded-Proto",
		Value: "https",
	})
	resp := w.Result()
	assert.DeepEqual(t, http.StatusMovedPermanently, resp.StatusCode())
	assert.DeepEqual(t, "https://www.example.com/foo", w.Header().Get("Location"))
}

func TestProxySSLWithHeaderOption(t *testing.T) {
	h := server.New(server.WithHostPorts("127.0.0.1:8001"))
	h.Use(New(
		WithSSLRedirect(true),
		WithSSLProxyHeaders(map[string]string{"X-Arbitrary-Header": "arbitrary-value"}),
	))
	h.GET("/foo", func(_ context.Context, c *app.RequestContext) {
		c.String(200, testResponse)
	})
	go h.Spin()
	time.Sleep(200 * time.Millisecond)
	client := http.Client{}
	req1, _ := http.NewRequest(consts.MethodGet, "http://127.0.0.1:8001/foo", nil)
	req1.Host = "www.example.com"
	req1.URL.Scheme = "http"
	req1.Header.Add("X-Arbitrary-Header", "arbitrary-value")
	resp, _ := client.Do(req1)
	assert.DeepEqual(t, http.StatusOK, resp.StatusCode)
}

func TestProxySSLWithWrongHeaderValue(t *testing.T) {
	engine := newServer(
		WithSSLRedirect(true),
		WithSSLProxyHeaders(map[string]string{"X-Arbitrary-Header": "arbitrary-value"}),
	)

	resp := performRequest(engine, "http://www.example.com/foo", ut.Header{
		Key:   "X-Arbitrary-Header",
		Value: "wrong-value",
	})
	assert.DeepEqual(t, http.StatusMovedPermanently, resp.StatusCode())
	assert.DeepEqual(t, "https://www.example.com/foo", resp.Header.Get("Location"))
}

func TestStsHeader(t *testing.T) {
	router := newServer(
		WithSTSSecond(315360000),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "max-age=315360000", w.Header.Get("Strict-Transport-Security"))
}

func TestStsHeaderInDevMode(t *testing.T) {
	router := newServer(
		WithSTSSecond(315360000),
		WithIsDevelopment(true),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "", w.Header.Get("Strict-Transport-Security"))
}

func TestStsHeaderWithSubdomain(t *testing.T) {
	router := newServer(
		WithSTSSecond(315360000),
		WithSTSIncludeSubdomains(true),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "max-age=315360000; includeSubdomains", w.Header.Get("Strict-Transport-Security"))
}

func TestFrameDeny(t *testing.T) {
	router := newServer(
		WithFrameDeny(true),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "DENY", w.Header.Get("X-Frame-Options"))
}

func TestCustomFrameValue(t *testing.T) {
	router := newServer(
		WithCustomFrameOptionsValue("SAMEORIGIN"),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "SAMEORIGIN", w.Header.Get("X-Frame-Options"))
}

func TestCustomFrameValueWithDeny(t *testing.T) {
	router := newServer(
		WithFrameDeny(true),
		WithCustomFrameOptionsValue("SAMEORIGIN"),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "SAMEORIGIN", w.Header.Get("X-Frame-Options"))
}

func TestContentNosniff(t *testing.T) {
	router := newServer(
		WithContentTypeNosniff(true),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "nosniff", w.Header.Get("X-Content-Type-Options"))
}

func TestXSSProtection(t *testing.T) {
	router := newServer(
		WithBrowserXssFilter(true),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "1; mode=block", w.Header.Get("X-XSS-Protection"))
}

func TestReferrerPolicy(t *testing.T) {
	router := newServer(
		WithReferrerPolicy("strict-origin-when-cross-origin"),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "strict-origin-when-cross-origin", w.Header.Get("Referrer-Policy"))
}

func TestFeaturePolicy(t *testing.T) {
	router := newServer(
		WithFeaturePolicy("vibrate 'none';"),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "vibrate 'none';", w.Header.Get("Feature-Policy"))
}

func TestCsp(t *testing.T) {
	router := newServer(
		WithContentSecurityPolicy("default-src 'self'"),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "default-src 'self'", w.Header.Get("Content-Security-Policy"))
}

func TestInlineSecure(t *testing.T) {
	router := newServer(
		WithFrameDeny(true),
	)

	w := performRequest(router, "/foo")

	assert.DeepEqual(t, http.StatusOK, w.StatusCode())
	assert.DeepEqual(t, "DENY", w.Header.Get("X-Frame-Options"))
}

func TestIsIpv4Host(t *testing.T) {
	assert.DeepEqual(t, isIPV4("127.0.0.1"), true)
	assert.DeepEqual(t, isIPV4("127.0.0.1:8080"), true)
	assert.DeepEqual(t, isIPV4("localhost"), false)
	assert.DeepEqual(t, isIPV4("localhost:8080"), false)
	assert.DeepEqual(t, isIPV4("example.com"), false)
	assert.DeepEqual(t, isIPV4("example.com:8080"), false)
}

func performRequest(engine *route.Engine, url string, header ...ut.Header) *protocol.Response {
	return ut.PerformRequest(engine, consts.MethodGet, url, nil).Result()
}
