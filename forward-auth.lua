-- Generic forward-auth action for HAProxy 3.2.
-- Authentication requests and propagated response headers use allowlists.

local AUTH_URL = os.getenv("FORWARD_AUTH_URL")
local AUTH_METHOD = string.upper(os.getenv("FORWARD_AUTH_METHOD") or "GET")
local AUTH_TIMEOUT_MS = tonumber(os.getenv("FORWARD_AUTH_TIMEOUT_MS")) or 3000
local MAX_HEADER_VALUE_LENGTH = 16384

local function header_list(environment_name, default)
  local result, seen = {}, {}
  local value = os.getenv(environment_name) or default or ""
  for item in value:gmatch("[^,]+") do
    local name = string.lower((item:match("^%s*(.-)%s*$")))
    if name ~= "" and name:match("^[a-z0-9][a-z0-9%-]*$") and not seen[name] then
      table.insert(result, name)
      seen[name] = true
    end
  end
  return result
end

local REQUEST_HEADERS = header_list(
  "FORWARD_AUTH_REQUEST_HEADERS",
  "cookie,authorization,user-agent,accept"
)
local UPSTREAM_HEADERS = header_list("FORWARD_AUTH_UPSTREAM_HEADERS")
local CLIENT_HEADERS = header_list("FORWARD_AUTH_CLIENT_HEADERS")

local function first_header(headers, name)
  local values = headers[name]
  if values == nil then return nil end
  local value = values[0] or values[1]
  if type(value) ~= "string" or #value > MAX_HEADER_VALUE_LENGTH then
    return nil
  end
  return value
end

local function request_header(headers, name)
  local value = first_header(headers, name)
  if value == nil or value == "" then return nil end
  return { value }
end

local function header_variable(prefix, name)
  return prefix .. (name:gsub("-", "_"))
end

local function clear_result(txn)
  txn:unset_var("txn.forward_auth_status")
  txn:unset_var("txn.forward_auth_www_authenticate")
  for _, name in ipairs(CLIENT_HEADERS) do
    txn:unset_var(header_variable("txn.forward_auth_client_header_", name))
  end
end

local function set_result(txn, result, status, response_headers)
  txn:set_var("txn.forward_auth_result", result)
  clear_result(txn)
  if status ~= nil then txn:set_var("txn.forward_auth_status", status) end

  if result == "unauthorized" then
    local authenticate = first_header(response_headers or {}, "www-authenticate")
    if authenticate ~= nil then
      txn:set_var("txn.forward_auth_www_authenticate", authenticate)
    end
  end

  for _, name in ipairs(CLIENT_HEADERS) do
    local value = first_header(response_headers or {}, name)
    if value ~= nil then
      txn:set_var(header_variable("txn.forward_auth_client_header_", name), value)
    end
  end
end

local function valid_host(host)
  host = string.lower((host:gsub(":%d+$", "")))
  if host == "" or not host:match("^[a-z0-9][a-z0-9.-]*[a-z0-9]$") then
    return nil
  end
  return host
end

local function forward_auth(txn)
  local request_headers = txn.http:req_get_headers()

  -- Client-supplied identity must not survive any error path.
  for _, name in ipairs(UPSTREAM_HEADERS) do
    txn.http:req_del_header(name)
  end

  if AUTH_URL == nil or AUTH_URL == "" then
    txn:Warning("forward-auth result=error reason=missing-auth-url")
    set_result(txn, "error", nil, nil)
    return
  end
  if AUTH_METHOD ~= "GET" and AUTH_METHOD ~= "HEAD" then
    txn:Warning("forward-auth result=error reason=invalid-auth-method")
    set_result(txn, "error", nil, nil)
    return
  end

  local host = first_header(request_headers, "host")
  if host == nil then
    set_result(txn, "error", nil, nil)
    return
  end
  host = valid_host(host)
  if host == nil then
    set_result(txn, "error", nil, nil)
    return
  end

  local method = txn.sf:method()
  local request_url = txn.sf:url()
  local client_ip = txn.sf:src()
  local origin = "https://" .. host
  local original_url
  if request_url:sub(1, #origin + 1) == origin .. "/" then
    original_url = request_url
  elseif request_url:sub(1, 1) == "/" then
    original_url = origin .. request_url
  else
    set_result(txn, "error", nil, nil)
    return
  end

  local auth_headers = {
    host = { host },
    ["x-original-url"] = { original_url },
    ["x-real-ip"] = { client_ip },
    ["x-forwarded-for"] = { client_ip },
    ["x-forwarded-host"] = { host },
    ["x-forwarded-method"] = { method },
    ["x-forwarded-proto"] = { "https" },
    connection = { "close" },
  }
  for _, name in ipairs(REQUEST_HEADERS) do
    local value = request_header(request_headers, name)
    if value ~= nil then auth_headers[name] = value end
  end

  local ok, response = pcall(function()
    local client = core.httpclient()
    local options = {
      url = AUTH_URL,
      headers = auth_headers,
      timeout = AUTH_TIMEOUT_MS,
    }
    if AUTH_METHOD == "HEAD" then return client:head(options) end
    return client:get(options)
  end)
  if not ok or type(response) ~= "table" or type(response.status) ~= "number" then
    txn:Warning("forward-auth result=error reason=invalid-httpclient-response")
    set_result(txn, "error", nil, nil)
    return
  end

  local status = response.status
  local response_headers = response.headers or {}
  if status >= 200 and status <= 299 then
    for _, name in ipairs(UPSTREAM_HEADERS) do
      local value = first_header(response_headers, name)
      if value ~= nil then txn.http:req_set_header(name, value) end
    end
    set_result(txn, "allow", status, response_headers)
  elseif status == 401 then
    set_result(txn, "unauthorized", status, response_headers)
  elseif status == 403 then
    set_result(txn, "forbidden", status, response_headers)
  else
    txn:Warning("forward-auth result=error status=" .. tostring(status))
    set_result(txn, "error", status, nil)
  end
end

core.register_action("forward-auth", { "http-req" }, function(txn)
  local ok, message = pcall(forward_auth, txn)
  if not ok then
    txn:Warning("forward-auth result=error exception=" .. tostring(message))
    set_result(txn, "error", nil, nil)
  end
end)
