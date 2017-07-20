package http_ipfilter_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bplotka/go-ipfilter"
	"github.com/Bplotka/go-ipfilter/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_FromxForwarderForHeader(t *testing.T) {
	lbIP, err := ipfilter.ParseIP("30.20.12.43")
	require.NoError(t, err)

	for _, spec := range []struct {
		xForwarderForHeader string
		reqRemoteAddr       string
		allowedIP           string
	}{
		{
			xForwarderForHeader: "127.0.2.1",
			reqRemoteAddr:       "80.80.80.80",
			allowedIP:           "80.80.80.80",
		},
		{
			xForwarderForHeader: "80.10.12.33, 127.0.2.1",
			reqRemoteAddr:       "80.80.80.80",
			allowedIP:           "80.10.12.33",
		},
		{
			xForwarderForHeader: "80.10.12.33, 30.20.12.43",
			reqRemoteAddr:       "80.80.80.80",
			allowedIP:           "80.10.12.33",
		},
		{
			xForwarderForHeader: "80.10.12.33, 30.20.12.43, 127.0.2.1",
			reqRemoteAddr:       "80.80.80.80",
			allowedIP:           "80.10.12.33",
		},
		{
			xForwarderForHeader: "127.0.2.1, 80.10.12.33, 30.20.12.43, 10.0.2.1, 127.0.2.1",
			reqRemoteAddr:       "80.80.80.80",
			allowedIP:           "80.10.12.33",
		},
	} {

		middleware := http_ipfilter.Middleware(
			[]net.IPNet{ipfilter.SingleIPNet(lbIP)},
			func(ip net.IP) bool {
				return ip.String() == spec.allowedIP
			}, func(_ http.ResponseWriter, err error) {
				t.Errorf("Middleware should allow access in case %+v. Err: %v", spec, err)
			},
		)
		continued := false
		handler := middleware(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			continued = true
		}))

		r := httptest.NewRequest("GET", "http://127.0.0.1", nil)
		r.RemoteAddr = spec.reqRemoteAddr
		r.Header.Set("X-Forwarded-For", spec.xForwarderForHeader)
		handler.ServeHTTP(nil, r)

		assert.True(t, continued, "Middleware should run next handler in case %+v", spec)
	}
}
