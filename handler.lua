-- Copyright 2020 Patrick Huck

local BasePlugin = require "kong.plugins.base_plugin"
local kong_utils = require "kong.tools.utils"
local constants = require "kong.constants"
local digest = require "openssl.digest"
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"

local kong = kong
local CustomHandler = BasePlugin:extend()

CustomHandler.VERSION  = "0.0-0"
CustomHandler.PRIORITY = 1004

function CustomHandler:new()
    CustomHandler.super.new(self, "grant-proxy-oauth")
end

function CustomHandler:access(config)
    CustomHandler.super.access(self)
    local access_token = kong.request.get_query_arg("access_token")
    local encrypted_token = ngx.var.cookie_EOAuthToken

    if encrypted_token then
        local access_token = decode_token(encrypted_token, config)
        if not access_token then
          return redirect_to_auth(config)
        end
    elseif access_token then
        -- set access token cookie
        local encoded_token = encode_token(access_token, config)
        local cookie_opts = "path=/;Max-Age=" .. config.auth_token_expire_time .. ";HttpOnly"
        kong.response.set_header("Set-Cookie", "EOAuthToken=" .. encoded_token  .. ";" .. cookie_opts)

        -- consumer
        local username = kong.request.get_query_arg("profile[email]")
        if username then
            local consumer_cache_key = kong.db.consumers:cache_key(username)
            local consumer, err = kong.cache:get(consumer_cache_key, nil, load_consumer_by_username, username)
            if err then
                return kong.response.exit(500, {message = err})
            else
                ngx.ctx.authenticated_consumer = consumer
                local acls_cache_key = kong.db.acls:cache_key(consumer.id)
                local groups, err = kong.cache:get(acls_cache_key, nil, load_groups_into_memory, {id = consumer.id})
                if err then
                    return kong.response.exit(500, {message = err})
                else
                    ngx.ctx.authenticated_groups = groups
                    local apikeys_cache_key = kong.db.keyauth_credentials:cache_key(consumer.id)
                    local apikeys, err = kong.cache:get(apikeys_cache_key, nil, load_apikeys_into_memory, {id = consumer.id})
                    if err then
                        return kong.response.exit(500, {message = err})
                    else
                        ngx.ctx.authenticated_credential = {id = "apikey", consumer_id = consumer.id}
                        local set_header = kong.service.request.set_header
                        set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
                        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, apikeys[#apikeys])
                        set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
                        set_header(constants.HEADERS.CONSUMER_GROUPS, table.concat(groups, ","))
                        -- TODO set_header(constants.HEADERS.ANONYMOUS, true) see basic_auth plugin
                    end
                end
            end
        else
            return kong.response.exit(500, {message = "email not found in user profile"})
        end

        -- Support redirection back to your request if necessary
        local redirect_back = ngx.var.cookie_EOAuthRedirectBack
        if redirect_back then
            return ngx.redirect(redirect_back)
        else
            return ngx.redirect(ngx.ctx.router_matches)
        end
    else
        -- return kong.response.exit(401, {message = "User has denied access to the resources."})
        return redirect_to_auth(config)
    end
end

function redirect_to_auth(config)
    -- TODO not on ajax, anonymous consumer, loop providers?
    local rb_cookie = "EOAuthRedirectBack=" .. ngx.var.request_uri .. "; path=/;Max-Age=120"
    kong.response.set_header("Set-Cookie", rb_cookie)
    -- TODO go to grunt server through internal network here? config.host = sso.materialsproject.org
    local connect = config.host .. "/connect/" .. config.provider
    local scheme = kong.request.get_scheme()
    local host = kong.request.get_host()
    local port = kong.request.get_port()
    local path = kong.request.get_path_with_query()
    local callback = scheme .. "://" .. host .. ":" .. port .. path
    return ngx.redirect(connect .. "?callback=" .. callback)
end

function binary_to_hex(string)
    return (string:gsub('.', function (char)
        return string.format('%02X', string.byte(char))
    end))
end

function hex_to_binary(string)
    return (string:gsub('..', function (chars)
        return string.char(tonumber(chars, 16))
    end))
end

function encrypt(type, key, plaintext)
    -- generate random initialization vector
    local iv = rand.bytes(16)
    return binary_to_hex(
        iv .. cipher.new(type):encrypt(key, iv):final(plaintext)
    )
end

function decrypt(type, key, encrypted)
    -- first 16 bytes are the initialization vector
    local iv = hex_to_binary(encrypted:sub(0 + 1, 31 + 1))
    local string = hex_to_binary(encrypted:sub(32 + 1))
    return cipher.new(type):decrypt(key, iv):final(string)
end

function encode_token(token, config)
    local md5_secret = digest.new("md5"):final(config.secret)
    return ngx.encode_base64(encrypt("aes-128-cbc", md5_secret, token))
end

function decode_token(token, config)
    local md5_secret = digest.new("md5"):final(config.secret)
    return decrypt("aes-128-cbc", md5_secret, ngx.decode_base64(token))
end

function load_consumer_by_username(consumer_username)
    local consumer, err = kong.db.consumers:select_by_username(consumer_username)

    if not consumer then
        if err then
            return nil, err
        else
            -- create consumer when not found in cache and no error occured
            local consumer, err = kong.db.consumers:insert({
                id = kong_utils.uuid(),
                username = consumer_username
            })
            if err then
                return nil, err
            else
                local key_credential, err = kong.db.keyauth_credentials:insert({
                    consumer = consumer
                })
                if err then
                    return nil, err
                end
            end
        end
    end

    return consumer
end

function load_groups_into_memory(consumer_pk)
    local groups = {}
    local len = 0

    for row, err in kong.db.acls:each_for_consumer(consumer_pk) do
        if err then
            return nil, err
        end
        len = len + 1
        groups[len] = row
    end

    return groups
end

function load_apikeys_into_memory(consumer_pk)
    local apikeys = {}
    local len = 0

    for row, err in kong.db.keyauth_credentials:each_for_consumer(consumer_pk) do
        if err then
            return nil, err
        end
        len = len + 1
        apikeys[len] = ngx.encode_base64(row)
    end

    return apikeys
end

return CustomHandler
