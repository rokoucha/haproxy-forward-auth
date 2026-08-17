# haproxy-forward-auth

[![CI](https://github.com/rokoucha/haproxy-forward-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/rokoucha/haproxy-forward-auth/actions/workflows/ci.yml)

An HAProxy 3.2 Lua HTTP request action for using an
[Authentik forward-auth outpost](https://docs.goauthentik.io/add-secure-apps/providers/proxy/server_haproxy/).

The action fails closed, strips client-supplied Authentik identity headers, and
only forwards an explicit allowlist of request headers to the authentication
service. It registers as `lua.forward-auth`.

## HAProxy configuration

Load `forward-auth.lua`, then handle the transaction variables set by the
action:

```haproxy
global
  lua-load /etc/haproxy/forward-auth.lua
  httpclient.timeout.connect 3s
  httpclient.retries 0

backend protected
  http-request lua.forward-auth
  http-request redirect code 302 location %[var(txn.forward_auth_location)] if { var(txn.forward_auth_result) -m str unauthorized }
  http-request deny deny_status 403 if { var(txn.forward_auth_result) -m str forbidden }
  http-request deny deny_status 503 if { var(txn.forward_auth_result) -m str error }
  http-response add-header Set-Cookie %[var(txn.forward_auth_set_cookie)] if { var(txn.forward_auth_set_cookie) -m found }
```

By default the authentication endpoint is
`http://127.0.0.1:10080/outpost.goauthentik.io/auth/nginx`. Set
`FORWARD_AUTH_URL` in HAProxy's environment to override it.

The action expects TLS to terminate at HAProxy and therefore constructs
`X-Original-URL` and forwarding headers with the `https` scheme.

## Tests

The test suite uses
[Busted](https://lunarmodules.github.io/busted/) with mocked HAProxy Lua APIs.
Build and run it with Docker:

```console
docker build -t haproxy-forward-auth-test .
docker run --rm haproxy-forward-auth-test
```
