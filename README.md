# Secure (This is a community driven project)

`Secure` middleware for hertz framework.

This repo is forked from [sessions](https://github.com/gin-contrib/secure) and adapted for hertz.

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

| Option                | Default Value                                   | Description                                                  |
| --------------------- | ----------------------------------------------- | ------------------------------------------------------------ |
| SSLRedirect           | true                                            | If `SSLRedirect` is set to true, then only allow https requests |
| IsDevelopment         | false                                           | When true, the whole security policy applied by the middleware is disabled completely. |
| STSSeconds            | 315360000                                       | Default is 315360000, which would NOT include the header.    |
| STSIncludeSubdomains  | true                                            | If `STSIncludeSubdomains` is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false. |
| FrameDeny             | true                                            | If `FrameDeny` is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false |
| ContentTypeNosniff    | true                                            | If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false. |
| BrowserXssFilter      | true                                            | If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false. |
| ContentSecurityPolicy | "default-src 'self'",                           | ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "". |
| IENoOpen              | true                                            | Prevent Internet Explorer from executing downloads in your site’s context |
| SSLProxyHeaders       | map[string]string{"X-Forwarded-Proto": "https"} | This is useful when your app is running behind a secure proxy that forwards requests to your app over http (such as on Heroku). |

## License

This project is under Apache License. See the [LICENSE](LICENSE) file for the full license text.