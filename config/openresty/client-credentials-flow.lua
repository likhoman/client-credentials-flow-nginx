local require = require

local http = require("resty.http")

local cjson_s = require("cjson.safe")
local inspect = require("inspect")
local auth2_resp_repos =  require("repository.auth2_resp_repos")

local ngx = ngx

local tab_concat = table.concat
local b64 = ngx.encode_base64

local log = ngx.log
local ERROR = ngx.ERR
local DEBUG = ngx.DEBUG

-- Template body for client credentials flow
local kc_body = {
    grant_type = 'client_credentials',
}

local _M = {}

local function challenge(realm)
    ngx.header.www_authenticate = tab_concat { "Basic realm=\"", realm, "\"" }
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local function parse_json_response(response)
    local err
    local res

    -- check the response from the OP
    if response.status ~= 200 then
        err = "response indicates failure, status=" .. response.status .. ", body=" .. response.body
    else

        -- decode the response and extract the JSON object
        res = cjson_s.decode(response.body)

        if not res then
            err = "JSON decoding failed"
        end
    end

    return res, err
end

local function configure_timeouts(httpc, timeout)
    if timeout then
        if type(timeout) == "table" then
            local r, e = httpc:set_timeouts(timeout.connect or 0, timeout.send or 0, timeout.read or 0)
        else
            local r, e = httpc:set_timeout(timeout)
        end
    end
end

local function authorize(opts)

    local headers = ngx.req.get_headers()
    local c_id = headers["client-id"]
    local c_secret = headers["client-secret"]

    local cached_auth_resp = auth2_resp_repos:get_response(c_id)

    if cached_auth_resp then
        return cached_auth_resp
    end

    local kc_headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["Authorization"] = "Basic " .. b64(ngx.escape_uri(c_id) .. ":" .. ngx.escape_uri(c_secret))
    }

    local endpoint = opts.token_endpoint
    local httpc = http.new()
    configure_timeouts(httpc, opts.timeout)
    local res, err = httpc:request_uri(endpoint, {
        method = "POST",
        body = ngx.encode_args(kc_body),
        headers = kc_headers,
        ssl_verify = (opts.ssl_verify ~= "no"),
        keepalive = (opts.keepalive ~= "no")
    })

    if (err or not res) then
        err = "accessing token endpoint (" .. endpoint .. ") failed: " .. err
        log(ERROR, err)
        challenge(opts.realm)
    end

    local auth_resp, err = parse_json_response(res)
    if err then
        log(ERROR, err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    log(DEBUG, inspect(auth_resp))

    auth2_resp_repos:save(c_id, auth_resp)

    return auth_resp
end

function _M.auth(opts)
    local auth_resp = authorize(opts)
    ngx.header["Authentication"] = auth_resp.token_type:gsub("^%l", string.upper) .. " " .. auth_resp.access_token
end

return _M