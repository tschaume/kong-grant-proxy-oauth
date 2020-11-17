-- Copyright 2020 Patrick Huck

local BasePlugin = require "kong.plugins.base_plugin"
local kong_utils = require "kong.tools.utils"
local constants = require "kong.constants"

local kong = kong
local error = error
local concat = table.concat
local CustomHandler = BasePlugin:extend()

CustomHandler.VERSION  = "0.0-0"
CustomHandler.PRIORITY = 1004

function CustomHandler:new()
    CustomHandler.super.new(self, "grant-proxy-oauth")
end

function CustomHandler:access(config)
    if config.anonymous and kong.client.get_credential() then
        -- we're already authenticated, and we're configured for using anonymous,
        -- hence we're in a logical OR between auth methods and we're already done.
        return
    end

    CustomHandler.super.access(self)
    local error_message = kong.request.get_query_arg("error_description")
    if error_message then
        return kong.response.error(403, error_message)
    end

    local access_token = kong.request.get_query_arg("access_token")
    if not access_token then
        return redirect_to_auth(config)
    end

    local ok, err = do_authentication(config)
    if not ok then
        if conf.anonymous then
            local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
            local consumer, err = kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, conf.anonymous, true)
            if err then
                return kong.response.error(500, "Invalid plugin config: Anonymous user not set.")
            end
            kong.client.authenticate(consumer)
        else
            return kong.response.error(err.status, err.message, err.headers)
        end
    end

    local redirect_back = ngx.var.cookie_EOAuthRedirectBack
    return ngx.redirect(redirect_back)
end

function do_authentication(config)
    local username = kong.request.get_query_arg("profile[email]")
    if not username then
        return nil, {status = 401, message = config.provider .. "does not provide email."}
    end

    local consumer, err = kong.client.load_consumer(username, true)
    if not consumer then
        if err then
            kong.log.err(err)
            return nil, {status = 500, message = err}
        else
            -- create consumer and associated api key
            consumer, err = kong.db.consumers:insert({id = kong_utils.uuid(), username = username})
            if err then
                return nil, {status = 500, message = err}
            else
                local credential, err = kong.db.keyauth_credentials:insert({consumer = consumer})
                if err then
                    return nil, {status = 500, message = err}
                end
                apikey = ngx.encode_base64(credential.key)
                local consumer, err = kong.db.consumers:update({id = consumer.id}, {custom_id = apikey})
                if err then
                    return nil, {status = 500, message = err}
                end
            end
        end
    end

    local cache_key = kong.db.keyauth_credentials:cache_key(consumer.id)
    local credential, err = kong.cache:get(cache_key, nil, load_credential, {id = consumer.id})
    if err then
        kong.log.err(err)
        return nil, {status = 500, message = err}
    end

    kong.client.authenticate(consumer, credential)
    return true
end

function redirect_to_auth(config)
    -- TODO not on ajax, loop providers?
    -- TODO go to grunt server through internal network here? config.host = sso.materialsproject.org
    local rb_cookie = "EOAuthRedirectBack=" .. ngx.var.request_uri .. "; path=/;Max-Age=120"
    kong.response.set_header("Set-Cookie", rb_cookie)
    local connect = config.host .. "/connect/" .. config.provider
    local scheme = kong.request.get_scheme()
    local host = kong.request.get_host()
    local port = kong.request.get_port()
    local path = kong.request.get_path_with_query()
    local callback = scheme .. "://" .. host .. ":" .. port .. path
    return ngx.redirect(connect .. "?callback=" .. callback)
end

function load_credential(consumer_pk)
    for row, err in kong.db.keyauth_credentials:each_for_consumer(consumer_pk) do
        if err then
            return nil, err
        end
        return row
    end
end

return CustomHandler
