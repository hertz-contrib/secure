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

	"github.com/cloudwego/hertz/pkg/app"
)

// Config is a struct for specifying configuration options for the secure.
type Config struct {
	// AllowedHosts is a list of fully qualified domain names that are allowed.
	// Default is empty list, which allows any and all host names.
	AllowedHosts []string
	// If SSLRedirect is set to true, then only allow https requests.
	// Default is false.
	SSLRedirect bool
	// If SSLTemporaryRedirect is true, the a 302 will be used while redirecting.
	// Default is false (301).
	SSLTemporaryRedirect bool
	// SSLHost is the host name that is used to redirect http requests to https.
	// Default is "", which indicates to use the same host.
	SSLHost string
	// STSSeconds is the max-age of the Strict-Transport-Security header.
	// Default is 0, which would NOT include the header.
	STSSeconds int64
	// If STSIncludeSubdomains is set to true, the `includeSubdomains` will
	// be appended to the Strict-Transport-Security header. Default is false.
	STSIncludeSubdomains bool
	// If FrameDeny is set to true, adds the X-Frame-Options header with
	// the value of `DENY`. Default is false.
	FrameDeny bool
	// CustomFrameOptionsValue allows the X-Frame-Options header value
	// to be set with a custom value. This overrides the FrameDeny option.
	CustomFrameOptionsValue string
	// If ContentTypeNosniff is true, adds the X-Content-Type-Options header
	// with the value `nosniff`. Default is false.
	ContentTypeNosniff bool
	// If BrowserXssFilter is true, adds the X-XSS-Protection header with
	// the value `1; mode=block`. Default is false.
	BrowserXssFilter bool
	// ContentSecurityPolicy allows the Content-Security-Policy header value
	// to be set with a custom value. Default is "".
	ContentSecurityPolicy string
	// HTTP header "Referrer-Policy" governs which referrer information, sent in the Referrer header, should be included with requests made.
	ReferrerPolicy string
	// When true, the whole security policy applied by the middleware is disabled completely.
	IsDevelopment bool
	// Handlers for when an error occurs (ie bad host).
	BadHostHandler app.HandlerFunc
	// Prevent Internet Explorer from executing downloads in your site’s context
	IENoOpen bool
	// Feature Policy is a new header that allows a site to control which features and APIs can be used in the browser.
	FeaturePolicy string
	// If DontRedirectIPV4Hostnames is true, requests to hostnames that are IPV4
	// addresses aren't redirected. This is to allow load balancer health checks
	// to succeed.
	DontRedirectIPV4Hostnames bool

	// If the request is insecure, treat it as secure if any of the headers in this dict are set to their corresponding value
	// This is useful when your app is running behind a secure proxy that forwards requests to your app over http (such as on Heroku).
	SSLProxyHeaders map[string]string
}

// DefaultConfig returns a Configuration with strict security settings.
// ```
//		SSLRedirect:           true
//		IsDevelopment:         false
//		STSSeconds:            315360000
//		STSIncludeSubdomains:  true
//		FrameDeny:             true
//		ContentTypeNosniff:    true
//		BrowserXssFilter:      true
//		ContentSecurityPolicy: "default-src 'self'"
//		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
// ```
func DefaultConfig() Config {
	return Config{
		SSLRedirect:           true,
		IsDevelopment:         false,
		STSSeconds:            315360000,
		STSIncludeSubdomains:  true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'",
		IENoOpen:              true,
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
	}
}

// New creates an instance of the secure middleware using the specified configuration.
// router.Use(secure.N)
func New(config Config) app.HandlerFunc {
	policy := newPolicy(config)
	return func(ctx context.Context, c *app.RequestContext) {
		if !policy.applyToContext(ctx, c) {
			return
		}
		c.Next(ctx)
	}
}
