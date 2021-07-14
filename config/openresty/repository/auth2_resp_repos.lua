local require = require

local ngx = ngx
local inspect = require("inspect")

local log = ngx.log
local DEBUG = ngx.DEBUG

local auth2_resp_repos = {
    -- The maximum acceptable clock skew, which is used when checking the access token expiry.
    clock_skew_sec = 60,
    cache_name = "auth_resp_cache"
}

-- set value in server-wide cache if available
local function cache_set(cache_name, key, value, exp)
    local dict = ngx.shared[cache_name]
    if dict and (exp > 0) then
        local success, err, forcible = dict:set(key, value, exp)
        log(DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
    end
end

-- retrieve value from server-wide cache if available
local function cache_get(cache_name, key)
    local dict = ngx.shared[cache_name]
    local value
    if dict then
        value = dict:get(key)
        if value then log(DEBUG, "cache hit: key=", key) end
    end
    return value
end

local function create_auth_resp_from_str (input_str)
    local t = {}
    if not input_str then return nil end
    for k, v in string.gmatch(input_str, "([(%a+)_(%a+)]+)=([(%w+)(.+)(%p+)]+)") do
        log(DEBUG, "key=" ..  k .. " value=" .. v)
        t[k] = v
    end
    log(DEBUG, inspect(t))
    return t
end

function auth2_resp_repos:get_response(client_id)
    return create_auth_resp_from_str(cache_get(self.cache_name, client_id))
end

function auth2_resp_repos:save(client_id, auth_resp)
    log(DEBUG, "JSON auth response:", inspect(auth_resp))
    local expires_time = (tonumber(auth_resp.expires_in) or 90) - self.clock_skew_sec
    local cached_value = "access_token=" .. auth_resp.access_token .. " token_type=" .. auth_resp.token_type
    log(DEBUG, "cached_value:", cached_value)
    cache_set(self.cache_name, client_id, cached_value, expires_time)
end

function auth2_resp_repos:set_cache_name(cache_name)
    self.cache_name = cache_name
end

function auth2_resp_repos:set_clock_skew_in_sec(clock_skew_sec)
    self.clock_skew_sec = clock_skew_sec
end

return auth2_resp_repos