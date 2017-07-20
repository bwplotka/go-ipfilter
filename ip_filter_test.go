package ipfilter_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/Bplotka/go-ipfilter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	trueCond  = func(_ net.IP) bool { return true }
	falseCond = func(_ net.IP) bool { return false }
)

func TestOR(t *testing.T) {
	someIP, err := ipfilter.ParseIP("81.11.43.33")
	require.NoError(t, err)

	assert.False(t, ipfilter.OR()(someIP), "empty OR should return false.")

	assert.False(t, ipfilter.OR(falseCond)(someIP), "false == false")
	assert.True(t, ipfilter.OR(trueCond)(someIP), "true == true")

	assert.True(t, ipfilter.OR(trueCond, trueCond, trueCond)(someIP), "true OR true OR true == true")
	assert.False(t, ipfilter.OR(falseCond, falseCond, falseCond)(someIP), "false OR false OR false == false")
	assert.True(t, ipfilter.OR(falseCond, trueCond, falseCond)(someIP), "false OR true OR false == true")
}

func TestAND(t *testing.T) {
	someIP, err := ipfilter.ParseIP("81.11.43.33")
	require.NoError(t, err)

	assert.False(t, ipfilter.AND()(someIP), "empty AND should return false.")

	assert.False(t, ipfilter.AND(falseCond)(someIP), "false == false")
	assert.True(t, ipfilter.AND(trueCond)(someIP), "true == true")

	assert.True(t, ipfilter.AND(trueCond, trueCond, trueCond)(someIP), "true OR true OR true == true")
	assert.False(t, ipfilter.AND(falseCond, falseCond, falseCond)(someIP), "false OR false OR false == false")
	assert.False(t, ipfilter.AND(falseCond, trueCond, falseCond)(someIP), "false OR true OR false == false")
}

func TestIsWhitelisted(t *testing.T) {
	ip, err := ipfilter.ParseIP("81.11.43.33")
	require.NoError(t, err)

	cond := ipfilter.IsWhitelisted([]net.IPNet{ipfilter.SingleIPNet(ip)})
	for _, spec := range []struct {
		remote   string
		expected bool
	}{
		{
			remote:   "127.0.2.1:41241",
			expected: false,
		},
		{
			remote:   "10.2.1.4:9231",
			expected: false,
		},
		{
			remote:   "11.241.54.24:4124",
			expected: false,
		},
		{
			remote:   "[::1]:23124",
			expected: false,
		},
		{
			remote:   "172.31.23.41:9231",
			expected: false,
		},
		{
			remote:   "192.168.23.14:23123",
			expected: false,
		},
		{
			remote:   "81.11.43.33:23123",
			expected: true,
		},
		{
			remote:   "81.11.43.33",
			expected: true,
		},
		{
			remote:   "81.11.43.34:23123",
			expected: false,
		},
	} {
		ip, err := ipfilter.ParseIP(spec.remote)
		require.NoError(t, err, fmt.Sprintf("%v should be parsable", spec.remote))
		assert.Equal(t, spec.expected, cond(ip), fmt.Sprintf("Should work for %v", spec.remote))
	}
}

func TestIsPrivate(t *testing.T) {
	cond := ipfilter.IsPrivate()
	for _, spec := range []struct {
		remote   string
		expected bool
	}{
		{
			remote:   "127.0.2.1:41241",
			expected: true,
		},
		{
			remote:   "10.2.1.4:9231",
			expected: true,
		},
		{
			remote:   "11.241.54.32:4124",
			expected: false,
		},
		{
			remote:   "[::1]:23124",
			expected: true,
		},
		{
			remote:   "172.31.23.41:9231",
			expected: true,
		},
		{
			remote:   "192.168.23.14:23123",
			expected: true,
		},
		{
			remote:   "81.11.43.33:23123",
			expected: false,
		},
		{
			remote:   "81.11.43.33",
			expected: false,
		},
		{
			remote:   "81.11.43.34:23123",
			expected: false,
		},
	} {
		ip, err := ipfilter.ParseIP(spec.remote)
		require.NoError(t, err, fmt.Sprintf("%v should be parsable", spec.remote))
		assert.Equal(t, spec.expected, cond(ip), fmt.Sprintf("Should work for %v", spec.remote))
	}
}
