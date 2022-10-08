package secure

import (
	"context"
	"fmt"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
)

// New creates an instance of the secure middleware using the specified configuration.
// router.Use(secure.N)
func New(opts ...Option) app.HandlerFunc {
	policy := newPolicy(opts)
	return func(ctx context.Context, c *app.RequestContext) {
		if !policy.applyToContext(ctx, c) {
			return
		}
		c.Next(ctx)
	}
}

func newPolicy(opts []Option) *policy {
	policy := &policy{
		config: options{
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
	}
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
