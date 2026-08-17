describe("forward-auth", function()
  local action, response, request_options, client_error
  local environment, original_getenv

  local function values(entries)
    local result = {}
    for name, value in pairs(entries or {}) do result[name] = { [0] = value } end
    return result
  end

  local function transaction(options)
    options = options or {}
    local headers = values(options.headers or { host = "app.example.com" })
    local txn = { vars = {}, warnings = {}, deleted_headers = {}, set_headers = {} }
    txn.http = {
      req_get_headers = function() return headers end,
      req_del_header = function(_, name)
        txn.deleted_headers[name] = true
        headers[name] = nil
      end,
      req_set_header = function(_, name, value) txn.set_headers[name] = value end,
    }
    txn.sf = {
      method = function() return options.method or "GET" end,
      url = function() return options.url or "/private?a=b" end,
      src = function() return options.src or "192.0.2.10" end,
    }
    function txn:set_var(name, value) self.vars[name] = value end
    function txn:unset_var(name) self.vars[name] = nil end
    function txn:Warning(message) table.insert(self.warnings, message) end
    return txn
  end

  local function load_action(overrides)
    environment = { FORWARD_AUTH_URL = "http://auth.example.test/check" }
    for name, value in pairs(overrides or {}) do environment[name] = value end
    os.getenv = function(name) return environment[name] end
    dofile("forward-auth.lua")
  end

  before_each(function()
    action, request_options, client_error = nil, nil, nil
    response = { status = 204, headers = {} }
    original_getenv = os.getenv
    _G.core = {
      register_action = function(name, contexts, callback)
        assert.are.equal("forward-auth", name)
        assert.are.same({ "http-req" }, contexts)
        action = callback
      end,
      httpclient = function()
        local function request(_, options)
          request_options = options
          if client_error then error(client_error) end
          return response
        end
        return { get = request, head = request }
      end,
    }
  end)

  after_each(function()
    os.getenv = original_getenv
    _G.core = nil
  end)

  it("registers the HAProxy request action", function()
    load_action()
    assert.is_function(action)
  end)

  it("allows 2xx and sends only allowlisted headers", function()
    load_action()
    local txn = transaction({ headers = {
      host = "App.Example.com:443",
      cookie = "session=old",
      authorization = "Bearer token",
      upgrade = "websocket",
      ["sec-websocket-key"] = "secret",
    } })
    action(txn)
    assert.are.equal("allow", txn.vars["txn.forward_auth_result"])
    assert.are.equal(204, txn.vars["txn.forward_auth_status"])
    assert.are.equal("http://auth.example.test/check", request_options.url)
    assert.are.equal(3000, request_options.timeout)
    assert.are.same({ "app.example.com" }, request_options.headers.host)
    assert.are.same({ "https://app.example.com/private?a=b" }, request_options.headers["x-original-url"])
    assert.are.same({ "Bearer token" }, request_options.headers.authorization)
    assert.are.same({ "close" }, request_options.headers.connection)
    assert.is_nil(request_options.headers.upgrade)
    assert.is_nil(request_options.headers["sec-websocket-key"])
  end)

  it("supports HEAD and custom request headers", function()
    load_action({
      FORWARD_AUTH_METHOD = "HEAD",
      FORWARD_AUTH_TIMEOUT_MS = "1500",
      FORWARD_AUTH_REQUEST_HEADERS = "cookie, x-api-key",
    })
    local txn = transaction({ headers = {
      host = "app.example.com",
      authorization = "do-not-forward",
      ["x-api-key"] = "secret",
    } })
    action(txn)
    assert.are.equal(1500, request_options.timeout)
    assert.are.same({ "secret" }, request_options.headers["x-api-key"])
    assert.is_nil(request_options.headers.authorization)
  end)

  it("copies allowlisted response headers to the upstream request", function()
    load_action({ FORWARD_AUTH_UPSTREAM_HEADERS = "x-user, x-groups" })
    response = { status = 200, headers = values({
      ["x-user"] = "alice", ["x-groups"] = "admin,users", ["x-other"] = "ignored",
    }) }
    local txn = transaction({ headers = { host = "app.example.com", ["x-user"] = "mallory" } })
    action(txn)
    assert.is_true(txn.deleted_headers["x-user"])
    assert.is_true(txn.deleted_headers["x-groups"])
    assert.are.equal("alice", txn.set_headers["x-user"])
    assert.are.equal("admin,users", txn.set_headers["x-groups"])
    assert.is_nil(txn.set_headers["x-other"])
  end)

  it("captures allowlisted headers for the client response", function()
    load_action({ FORWARD_AUTH_CLIENT_HEADERS = "set-cookie, x-auth-token" })
    response = { status = 200, headers = values({
      ["set-cookie"] = "session=new; Secure", ["x-auth-token"] = "new-token",
    }) }
    local txn = transaction()
    action(txn)
    assert.are.equal("session=new; Secure", txn.vars["txn.forward_auth_client_header_set_cookie"])
    assert.are.equal("new-token", txn.vars["txn.forward_auth_client_header_x_auth_token"])
  end)

  it("maps 401 and propagates WWW-Authenticate", function()
    load_action()
    response = { status = 401, headers = values({
      ["www-authenticate"] = 'Basic realm="private"',
    }) }
    local txn = transaction()
    action(txn)
    assert.are.equal("unauthorized", txn.vars["txn.forward_auth_result"])
    assert.are.equal(401, txn.vars["txn.forward_auth_status"])
    assert.are.equal('Basic realm="private"', txn.vars["txn.forward_auth_www_authenticate"])
  end)

  it("maps 403 to forbidden and other statuses to error", function()
    load_action()
    response = { status = 403, headers = {} }
    local forbidden = transaction()
    action(forbidden)
    assert.are.equal("forbidden", forbidden.vars["txn.forward_auth_result"])
    response = { status = 302, headers = values({ location = "/login" }) }
    local redirect = transaction()
    action(redirect)
    assert.are.equal("error", redirect.vars["txn.forward_auth_result"])
    assert.are.equal(302, redirect.vars["txn.forward_auth_status"])
  end)

  it("fails closed when the auth URL is missing", function()
    load_action({ FORWARD_AUTH_URL = "" })
    local txn = transaction()
    action(txn)
    assert.are.equal("error", txn.vars["txn.forward_auth_result"])
    assert.matches("missing%-auth%-url", txn.warnings[1])
    assert.is_nil(request_options)
  end)

  it("removes spoofed upstream headers before malformed request errors", function()
    load_action({ FORWARD_AUTH_UPSTREAM_HEADERS = "x-user" })
    local txn = transaction({ headers = {
      host = "evil.example@trusted.example", ["x-user"] = "attacker",
    } })
    action(txn)
    assert.are.equal("error", txn.vars["txn.forward_auth_result"])
    assert.is_true(txn.deleted_headers["x-user"])
    assert.is_nil(request_options)
  end)

  it("fails closed when the auth service raises an error", function()
    load_action()
    client_error = "connection refused"
    local txn = transaction()
    action(txn)
    assert.are.equal("error", txn.vars["txn.forward_auth_result"])
    assert.matches("invalid%-httpclient%-response", txn.warnings[1])
  end)

  it("does not forward oversized request headers", function()
    load_action()
    local txn = transaction({ headers = {
      host = "app.example.com", authorization = string.rep("x", 16385),
    } })
    action(txn)
    assert.is_nil(request_options.headers.authorization)
  end)
end)
