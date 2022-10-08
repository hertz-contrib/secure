package secure

import (
	"context"
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
		config       options
		fixedHeaders *protocol.ResponseHeader
	}
)

func (p *policy) addHeader(key, value string) {
	p.fixedHeaders.Add(key, value)
}

func (p *policy) writeSecureHeaders(ctx context.Context, c *app.RequestContext) {
	header := &c.Response.Header
	p.fixedHeaders.VisitAll(func(k, v []byte) {
		header.Set(string(k), string(v))
	})
}

func (p *policy) applyToContext(ctx context.Context, c *app.RequestContext) bool {
	if !p.config.isDevelopment {
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

func (p *policy) checkAllowHosts(ctx context.Context, c *app.RequestContext) bool {
	if len(p.config.allowedHosts) == 0 {
		return true
	}
	host := c.Request.Host()
	if len(host) == 0 {
		host = c.Request.URI().Host()
	}
	for _, allowHost := range p.config.allowedHosts {
		if strings.EqualFold(allowHost, string(host)) {
			return true
		}
	}
	if p.config.badHostHandler != nil {
		p.config.badHostHandler(ctx, c)
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
	if !p.config.sslRedirect {
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

	if len(p.config.sslHost) > 0 {
		uri.SetHost(p.config.sslHost)
	}

	status := http.StatusMovedPermanently

	if p.config.sslTemporaryRedirect {
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
	for h, v := range p.config.sslProxyHeaders {
		get := req.Header.Get(h)
		if strings.EqualFold(get, v) {
			return true
		}
	}

	if p.config.dontRedirectIPV4Hostnames && isIPV4(string(req.Host())) {
		return true
	}

	return false
}
