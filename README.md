# IP Filter
[![Build Status](https://travis-ci.org/Bplotka/go-ipfilter.svg?branch=master)](https://travis-ci.org/Bplotka/go-ipfilter) [![Go Report Card](https://goreportcard.com/badge/github.com/Bplotka/go-ipfilter)](https://goreportcard.com/report/github.com/Bplotka/go-ipfilter)

Tiny Golang lib for IP filtering. 

This is helpful to restrict access to some endpoints on public service (e.g debug endpoints)

### Well, why not just use proper auth (e.g basic, oidc, oauth2)?

Because some endpoints are problematic to hide using auth, like debug or metrics endpoints.

## Usage

Filters are in a form of Bool conditions that takes IP in a form of `net.IP`

```go
type Condition func(net.IP) bool
````

You can chain multiple conditions with some logic using `ipfilter.OR(...)` `ipfilter.AND(...)`

This package also contain useful [HTTP middleware integration](./http/middleware.go).