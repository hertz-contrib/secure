# Secure (This is a community driven project)

`Secure` middleware for hertz framework.

This repo is forked from [secure](https://github.com/gin-contrib/secure) and adapted for hertz.

## Install

```bash
go get github.com/hertz-contrib/secure
```

### [Custom example](example/custom/main.go)

User passed in custom configuration items

#### Function Signature

```go
func New(opts ...Option) app.HandlerFunc
```

#### Sample Code

```go
package main

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/hertz-contrib/secure"
)

func main() {
	h := server.Default(
		server.WithHostPorts("127.0.0.1:8080"),
	)
	h.Use(secure.New(
		secure.WithAllowedHosts([]string{"example.com", "ssl.example.com"}),
		secure.WithSSLHost("ssl.example.com"),
	))

	h.GET("/ping", func(c context.Context, ctx *app.RequestContext) {
		ctx.String(200, "pong")
	})
	h.Spin()
}
```

## Default Configuration

```go
    config:
	options{
	    sslRedirect:           true,
	    isDevelopment:         false,
	    stsSeconds:            315360000,
	    frameDeny:             true,
	    contentTypeNosniff:    true,
	    browserXssFilter:      true,
	    contentSecurityPolicy: "default-src 'self'",
	    ieNoOpen:              true,
	    sslProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
       },
```

## Option

| options                       | Parameters        | value                       | Description                                                  |
| ----------------------------- | ----------------- |-----------------------------| ------------------------------------------------------------ |
| WithSSLRedirect               | bool              | true                        | If `WithSSLRedirect` is set to true, then only allow https requests |
| WithIsDevelopment             | bool              | false                       | When true, the whole security policy applied by the middleware is disabled completely. |
| WithSTSSecond                 | int64             | 315360000                   | Default is 315360000, which would NOT include the header.    |
| WithSTSIncludeSubdomains      | bool              | false                       | If `WithSTSIncludeSubdomains` is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false. |
| WithFrameDeny                 | bool              | false                       | If `WithFrameDeny` is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false |
| WithContentTypeNosniff        | bool              | false                       | If `WithContentTypeNosniff` is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false. |
| WithBrowserXssFilter          | bool              | false                       | If `WithBrowserXssFilter` is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false. |
| WithContentSecurityPolicy     | []string          | ""                          | `WithContentSecurityPolicy` allows the Content-Security-Policy header value to be set with a custom value. Default is "". |
| WithIENoOpen                  | bool              | false             | Prevent Internet Explorer from executing downloads in your site’s context |
| WithSSLProxyHeaders           | map[string]string | "X-Forwarded-Proto": "https" | This is useful when your app is running behind a secure proxy that forwards requests to your app over http (such as on Heroku). |
| WithAllowedHosts              | []string          | nil                         | `WithAllowedHosts` is a list of fully qualified domain names that are allowed.Default is empty list, which allows any and all host names. |
| WithSSLTemporaryRedirect      | bool              | false                    | If `WithSSLTemporaryRedirect` is true, the a 302 will be used while redirecting. Default is false (301). |
| WithSSLHost                   | string            | ""                          | `WithSSLHost` is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host. |
| WithCustomFrameOptionsValue   | string            | nil                         | `WithCustomFrameOptionsValue` allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option. |
| WithReferrerPolicy            | string            | nil                         | HTTP header "Referrer-Policy" governs which referrer information, sent in the Referrer header, should be included with requests made. |
| WithBadHostHandler            | app.HandlerFunc   | nil                         | Handlers for when an error occurs (ie bad host).             |
| WithFeaturePolicy             | string            | nil                         | Feature Policy is a new header that allows a site to control which features and APIs can be used in the browser. |
| WithDontRedirectIPV4Hostnames | bool              | false             | If `WithDontRedirectIPV4Hostnames` is true, requests to hostnames that are IPV4 addresses aren't redirected. This is to allow load balancer health checks  to succeed. |

## License

This project is under Apache License. See the [LICENSE](LICENSE) file for the full license text.