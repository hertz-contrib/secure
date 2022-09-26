# Secure (This is a community driven project)

`Secure` middleware for hertz framework.

This repo is forked from [secure](https://github.com/gin-contrib/secure) and adapted for hertz.

## Install

```bash
go get github.com/hertz-contrib/secure
```

### [Default example](example/default/main.go)

Default configuration for users to set security configuration directly using secure middleware

#### Function Signature

```go
func DefaultConfig() Config
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
	h := server.New(server.WithHostPorts(":8080"))
	securityConfig := secure.DefaultConfig()
	securityConfig.AllowedHosts = []string{"example.com", "ssl.example.com"}
	securityConfig.SSLHost = "ssl.example.com"
	h.Use(secure.New(securityConfig))
	h.GET("/ping", func(ctx context.Context, c *app.RequestContext) {
		c.String(200, "pong")
	})
	h.Spin()
}

```

### [Custom example](example/custom/main.go)

User passed in custom configuration items

#### Function Signature

```go
func New(config Config) app.HandlerFunc
```

#### Sample Code

```go
func main() {
h := server.Default(
server.WithHostPorts("127.0.0.1:8080"),
)
h.Use(secure.New(secure.Config{
AllowedHosts:          []string{"example.com", "ssl.example.com"},
SSLRedirect:           true,
SSLHost:               "ssl.example.com",
		STSSeconds:            315360000,
		STSIncludeSubdomains:  true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'",
		IENoOpen:              true,
ReferrerPolicy:        "strict-origin-when-cross-origin",
SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
}))

h.GET("/ping", func(c context.Context, ctx *app.RequestContext) {
ctx.String(200, "pong")
})
h.Spin()
}
```

## Default Configuration

```go
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
```

## Option

| Option                    | Properties        | Description                                                  |
| ------------------------- | ----------------- | ------------------------------------------------------------ |
| SSLRedirect               | bool              | If `SSLRedirect` is set to true, then only allow https requests |
| IsDevelopment             | bool              | When true, the whole security policy applied by the middleware is disabled completely. |
| STSSeconds                | int64             | Default is 315360000, which would NOT include the header.    |
| STSIncludeSubdomains      | bool              | If `STSIncludeSubdomains` is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false. |
| FrameDeny                 | bool              | If `FrameDeny` is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false |
| ContentTypeNosniff        | bool              | If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false. |
| BrowserXssFilter          | bool              | If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false. |
| ContentSecurityPolicy     | []string          | ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "". |
| IENoOpen                  | bool              | Prevent Internet Explorer from executing downloads in your site’s context |
| SSLProxyHeaders           | map[string]string | This is useful when your app is running behind a secure proxy that forwards requests to your app over http (such as on Heroku). |
| AllowedHosts              | []string          | AllowedHosts is a list of fully qualified domain names that are allowed.Default is empty list, which allows any and all host names. |
| SSLTemporaryRedirect      | bool              | If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301). |
| SSLHost                   | string            | SSLHost is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host. |
| CustomFrameOptionsValue   | string            | CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option. |
| ReferrerPolicy            | string            | HTTP header "Referrer-Policy" governs which referrer information, sent in the Referrer header, should be included with requests made. |
| BadHostHandler            | app.HandlerFunc   | Handlers for when an error occurs (ie bad host).             |
| FeaturePolicy             | string            | Feature Policy is a new header that allows a site to control which features and APIs can be used in the browser. |
| DontRedirectIPV4Hostnames | bool              | If DontRedirectIPV4Hostnames is true, requests to hostnames that are IPV4 addresses aren't redirected. This is to allow load balancer health checks  to succeed. |

## License

This project is under Apache License. See the [LICENSE](LICENSE) file for the full license text.