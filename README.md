# haproxy-forward-auth

[![CI](https://github.com/rokoucha/haproxy-forward-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/rokoucha/haproxy-forward-auth/actions/workflows/ci.yml)

An HAProxy 3.2 Lua action that authorizes requests through an external HTTP
service. Its status handling follows nginx
[`auth_request`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html):
2xx allows access, 401 and 403 deny access, and every other response fails
closed.

Authentication requests and propagated response headers are constructed from
explicit allowlists. The action registers as `lua.forward-auth`.

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
  http-request deny deny_status 401 if { var(txn.forward_auth_result) -m str unauthorized }
  http-request deny deny_status 403 if { var(txn.forward_auth_result) -m str forbidden }
  http-request deny deny_status 503 if { var(txn.forward_auth_result) -m str error }
  http-after-response set-header WWW-Authenticate %[var(txn.forward_auth_www_authenticate)] if { var(txn.forward_auth_www_authenticate) -m found }
```

`FORWARD_AUTH_URL` is required. The following environment variables are read
when HAProxy loads the script:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FORWARD_AUTH_URL` | required | Authentication endpoint |
| `FORWARD_AUTH_METHOD` | `GET` | Bodyless `GET` or `HEAD` request |
| `FORWARD_AUTH_TIMEOUT_MS` | `3000` | Authentication request timeout |
| `FORWARD_AUTH_REQUEST_HEADERS` | `cookie,authorization,user-agent,accept` | Client headers sent to the auth service |
| `FORWARD_AUTH_UPSTREAM_HEADERS` | empty | Auth response headers copied to the protected request |
| `FORWARD_AUTH_CLIENT_HEADERS` | empty | Auth response headers exposed as transaction variables |

An upstream response header such as `X-User` becomes a trusted request header
when listed in `FORWARD_AUTH_UPSTREAM_HEADERS`. The client-supplied version is
always removed before authentication.

A header such as `Set-Cookie` listed in `FORWARD_AUTH_CLIENT_HEADERS` is exposed
as `txn.forward_auth_client_header_set_cookie`. It can be returned with:

```haproxy
http-after-response add-header Set-Cookie %[var(txn.forward_auth_client_header_set_cookie)] if { var(txn.forward_auth_client_header_set_cookie) -m found }
```

On a 401 response, `WWW-Authenticate` is also exposed as
`txn.forward_auth_www_authenticate`.

The action expects TLS to terminate at HAProxy and therefore constructs
`X-Original-URL` and forwarding headers with the `https` scheme.

## Authentik example

Authentik can be configured without any provider-specific behavior in the Lua
action:

```text
FORWARD_AUTH_URL=http://127.0.0.1:10080/outpost.goauthentik.io/auth/nginx
FORWARD_AUTH_METHOD=HEAD
FORWARD_AUTH_UPSTREAM_HEADERS=x-authentik-username,x-authentik-groups,x-authentik-entitlements,x-authentik-email,x-authentik-name,x-authentik-uid,x-authentik-jwt,x-authentik-meta-jwks,x-authentik-meta-outpost,x-authentik-meta-provider,x-authentik-meta-app,x-authentik-meta-version
FORWARD_AUTH_CLIENT_HEADERS=set-cookie
```

If browser requests should be redirected to Authentik instead of receiving a
401, add that policy in HAProxy after `http-request lua.forward-auth`. This
keeps login URLs and redirect behavior out of the generic authorization action.

## Tests

The test suite uses
[Busted](https://lunarmodules.github.io/busted/) with mocked HAProxy Lua APIs.
Build and run it with Docker:

```console
docker build -t haproxy-forward-auth-test .
docker run --rm haproxy-forward-auth-test
```
