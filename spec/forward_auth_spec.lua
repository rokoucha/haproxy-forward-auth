describe("forward-auth", function()
  local action
  local response
  local request_options
  local client_error

  local function values(entries)
    local result = {}
    for name, value in pairs(entries or {}) do
      result[name] = { [0] = value }
    end
    return result
  end

  local function transaction(options)
    options = options or {}
    local headers = values(options.headers or { host = "app.example.com" })
    local txn = {
      vars = {},
      warnings = {},
      deleted_headers = {},
      set_headers = {},
    }

    txn.http = {
      req_get_headers = function()
        return headers
      end,
      req_del_header = function(_, name)
        txn.deleted_headers[name] = true
        headers[name] = nil
      end,
      req_set_header = function(_, name, value)
        txn.set_headers[name] = value
      end,
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

  before_each(function()
    action = nil
    response = { status = 204, headers = {} }
    request_options = nil
    client_error = nil
    _G.core = {
      register_action = function(name, contexts, callback)
        assert.are.equal("forward-auth", name)
        assert.are.same({ "http-req" }, contexts)
        action = callback
      end,
      httpclient = function()
        return {
          head = function(_, options)
            request_options = options
            if client_error then error(client_error) end
            return response
          end,
        }
      end,
    }
    dofile("forward-auth.lua")
  end)

  after_each(function()
    _G.core = nil
  end)

  it("registers the HAProxy request action", function()
    assert.is_function(action)
  end)

  it("allows successful authentication and propagates trusted identity", function()
    response = { status = 200, headers = values({
      ["x-authentik-username"] = "alice",
      ["set-cookie"] = "auth=refreshed; Secure",
    }) }
    local txn = transaction({ headers = {
      host = "App.Example.com:443",
      cookie = "auth=old",
      authorization = "Bearer token",
      ["user-agent"] = "test-agent",
      accept = "text/html",
      upgrade = "websocket",
      ["sec-websocket-key"] = "secret",
      ["x-authentik-username"] = "mallory",
    } })

    action(txn)

    assert.are.equal("allow", txn.vars["txn.forward_auth_result"])
    assert.are.equal("alice", txn.set_headers["x-authentik-username"])
    assert.are.equal("auth=refreshed; Secure", txn.vars["txn.forward_auth_set_cookie"])
    assert.is_true(txn.deleted_headers["x-authentik-username"])
    assert.are.equal("http://127.0.0.1:10080/outpost.goauthentik.io/auth/nginx", request_options.url)
    assert.are.equal(3000, request_options.timeout)
    assert.are.same({ "app.example.com" }, request_options.headers.host)
    assert.are.same({ "https://app.example.com/private?a=b" }, request_options.headers["x-original-url"])
    assert.are.same({ "Bearer token" }, request_options.headers.authorization)
    assert.are.same({ "close" }, request_options.headers.connection)
    assert.is_nil(request_options.headers.upgrade)
    assert.is_nil(request_options.headers["sec-websocket-key"])
  end)

  it("turns a 401 into an encoded authentik sign-in redirect", function()
    response = { status = 401, headers = values({ ["set-cookie"] = "session=new" }) }
    local txn = transaction({ url = "/private path?q=a&b=c" })

    action(txn)

    assert.are.equal("unauthorized", txn.vars["txn.forward_auth_result"])
    assert.are.equal(
      "/outpost.goauthentik.io/start?rd=https%3A%2F%2Fapp.example.com%2Fprivate%20path%3Fq%3Da%26b%3Dc",
      txn.vars["txn.forward_auth_location"]
    )
    assert.are.equal("session=new", txn.vars["txn.forward_auth_set_cookie"])
  end)

  it("preserves an absolute same-origin HTTP/2 URL", function()
    local txn = transaction({ url = "https://app.example.com/private" })
    action(txn)
    assert.are.same(
      { "https://app.example.com/private" },
      request_options.headers["x-original-url"]
    )
  end)

  it("maps a 403 response to forbidden", function()
    response = { status = 403, headers = {} }
    local txn = transaction()
    action(txn)
    assert.are.equal("forbidden", txn.vars["txn.forward_auth_result"])
  end)

  it("accepts only relative or same-origin auth redirects", function()
    for _, location in ipairs({ "/login", "https://app.example.com/login" }) do
      response = { status = 302, headers = values({ location = location }) }
      local txn = transaction()
      action(txn)
      assert.are.equal("unauthorized", txn.vars["txn.forward_auth_result"])
    end

    for _, location in ipairs({ "//evil.example/login", "https://evil.example/login" }) do
      response = { status = 302, headers = values({ location = location }) }
      local txn = transaction()
      action(txn)
      assert.are.equal("error", txn.vars["txn.forward_auth_result"])
    end
  end)

  it("fails closed and removes spoofed identity for malformed requests", function()
    local txn = transaction({ headers = {
      host = "evil.example@trusted.example",
      ["x-authentik-email"] = "attacker@example.com",
    } })
    action(txn)
    assert.are.equal("error", txn.vars["txn.forward_auth_result"])
    assert.is_true(txn.deleted_headers["x-authentik-email"])
    assert.is_nil(request_options)
  end)

  it("fails closed when the auth service raises an error", function()
    client_error = "connection refused"
    local txn = transaction()
    action(txn)
    assert.are.equal("error", txn.vars["txn.forward_auth_result"])
    assert.matches("invalid%-httpclient%-response", txn.warnings[1])
  end)

  it("does not forward oversized request headers", function()
    local txn = transaction({ headers = {
      host = "app.example.com",
      authorization = string.rep("x", 16385),
    } })
    action(txn)
    assert.is_nil(request_options.headers.authorization)
  end)
end)
