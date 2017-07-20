package http_ipfilter

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Bplotka/go-ipfilter"
)

// getProxiedIPAddress returns true remote address for client. This sometimes requires all publicProxies IP addresses or ranges,
// that can be involved into process. (e.g when hidden by Public Load Balancer, we need that Load Balancer address to tell real remote IP)
// publicProxyIPs are IPs that can be in X-Forwarded-For header as a hop, but should not be treated as remote addr.
// public addresses right before this IP will be treated as remote addr.
func getProxiedIPAddress(r *http.Request, publicProxyIPs []net.IPNet) net.IP {
	isNotRemote := ipfilter.OR(
		// Is not globalUnicast.
		func(ip net.IP) bool {
			return !ip.IsGlobalUnicast()
		},
		ipfilter.IsWhitelisted(publicProxyIPs),
		ipfilter.IsPrivate(),
	)

	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")

		// March from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			realIP, err := ipfilter.ParseIP(addresses[i])
			if err != nil {
				// Should not happen.
				return nil
			}

			if isNotRemote(realIP) {
				// Not an remote IP.
				continue
			}

			return realIP
		}
	}
	return nil
}

// Middleware filters out HTTP requests that are not meeting specified condition.
// publicProxyIPs are IPs that can be in X-Forwarded-For header as a hop, but should not be treated as remote addr.
// public addresses right before this IP will be treated as remote addr.
func Middleware(publicProxyIPs []net.IPNet, cond ipfilter.Condition, notAllowedFn func(http.ResponseWriter, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			ip := getProxiedIPAddress(req, publicProxyIPs)
			if ip == nil {
				var err error
				ip, err = ipfilter.ParseIP(req.RemoteAddr)
				if err != nil {
					notAllowedFn(resp, err)
				}
			}

			if !cond(ip) {
				notAllowedFn(resp, fmt.Errorf("IP %s failed filtering conditions", ip.String()))
			}

			next.ServeHTTP(resp, req)
		})
	}
}
