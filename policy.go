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
	"net"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
)

type (
	// Secure is a middleware that helps setup a few basic security features. A single secure.Options struct can be
	// provided to configure which features should be enabled, and the ability to override a few of the default values.
	policy struct {
		// Customize Secure with an Options struct.
		config       Config
		fixedHeaders *protocol.ResponseHeader
	}
)

func newPolicy(cfg Config) *policy {
	policy := &policy{}
	policy.loadConfig(cfg)
	return policy
}

func (p *policy) loadConfig(cfg Config) {
	p.config = cfg
	p.fixedHeaders = &protocol.ResponseHeader{}
	// Frame Options header.
	if len(cfg.CustomFrameOptionsValue) > 0 {
		p.addHeader("X-Frame-Options", cfg.CustomFrameOptionsValue)
	} else if cfg.FrameDeny {
		p.addHeader("X-Frame-Options", "DENY")
	}

	// Content Type Options header.
	if cfg.ContentTypeNosniff {
		p.addHeader("X-Content-Type-Options", "nosniff")
	}

	// XSS Protection header.
	if cfg.BrowserXssFilter {
		p.addHeader("X-Xss-Protection", "1; mode=block")
	}

	// Content Security Policy header.
	if len(cfg.ContentSecurityPolicy) > 0 {
		p.addHeader("Content-Security-Policy", cfg.ContentSecurityPolicy)
	}

	if len(cfg.ReferrerPolicy) > 0 {
		p.addHeader("Referrer-Policy", cfg.ReferrerPolicy)
	}

	// Strict Transport Security header.
	if cfg.STSSeconds != 0 {
		stsSub := ""
		if cfg.STSIncludeSubdomains {
			stsSub = "; includeSubdomains"
		}

		p.addHeader(
			"Strict-Transport-Security",
			fmt.Sprintf("max-age=%d%s", cfg.STSSeconds, stsSub))
	}

	// X-Download-Options header.
	if cfg.IENoOpen {
		p.addHeader("X-Download-Options", "noopen")
	}

	// FeaturePolicy header.
	if len(cfg.FeaturePolicy) > 0 {
		p.addHeader("Feature-Policy", cfg.FeaturePolicy)
	}
}

func (p *policy) addHeader(key, value string) {
	p.fixedHeaders.Add(key, value)
}

func (p *policy) applyToContext(ctx context.Context, c *app.RequestContext) bool {
	if !p.config.IsDevelopment {
		p.writeSecureHeaders(ctx, c)
		if !p.checkAllowHosts(ctx, c) {
			return false
		}
		if !p.checkSSL(ctx, c) {
			return false
		}

	}
	return true
}

func (p *policy) writeSecureHeaders(ctx context.Context, c *app.RequestContext) {
	header := &c.Response.Header
	p.fixedHeaders.VisitAll(func(k, v []byte) {
		header.Set(string(k), string(v))
	})
}

func (p *policy) checkAllowHosts(ctx context.Context, c *app.RequestContext) bool {
	if len(p.config.AllowedHosts) == 0 {
		return true
	}
	host := c.Request.Host()
	if len(host) == 0 {
		host = c.Request.URI().Host()
	}
	for _, allowHost := range p.config.AllowedHosts {
		if strings.EqualFold(allowHost, string(host)) {
			return true
		}
	}
	if p.config.BadHostHandler != nil {
		p.config.BadHostHandler(ctx, c)
	} else {
		c.AbortWithStatus(http.StatusForbidden)
	}
	return false
}

// checks if a host (possibly with trailing port) is an IPV4 address
func isIPV4(host string) bool {
	if index := strings.IndexByte(host, ':'); index != -1 {
		host = host[:index]
	}
	return net.ParseIP(host) != nil
}

func (p *policy) checkSSL(_ context.Context, c *app.RequestContext) bool {
	if !p.config.SSLRedirect {
		return true
	}

	req := &c.Request

	isSSLRequest := p.isSSLRequest(req)
	if isSSLRequest {
		return true
	}

	uri := req.URI()
	uri.SetScheme("https")
	uri.SetHost(string(req.Host()))

	if len(p.config.SSLHost) > 0 {
		uri.SetHost(p.config.SSLHost)
	}

	status := http.StatusMovedPermanently

	if p.config.SSLTemporaryRedirect {
		status = http.StatusTemporaryRedirect
	}
	c.Redirect(status, []byte(uri.String()))
	c.Abort()
	return false
}

func (p *policy) isSSLRequest(req *protocol.Request) bool {
	scheme := req.URI().Scheme()
	fold := strings.EqualFold(string(scheme), "https")
	if fold {
		return true
	}
	for h, v := range p.config.SSLProxyHeaders {
		get := req.Header.Get(h)
		if strings.EqualFold(get, v) {
			return true
		}
	}

	if p.config.DontRedirectIPV4Hostnames && isIPV4(string(req.Host())) {
		return true
	}

	return false
}