-- Copyright 2020 Patrick Huck

local BasePlugin = require "kong.plugins.base_plugin"
local kong_utils = require "kong.tools.utils"
local groups = require "kong.plugins.acl.groups"

local kong = kong
local CustomHandler = BasePlugin:extend()

CustomHandler.VERSION  = "0.0-0"
CustomHandler.PRIORITY = 1004

function CustomHandler:new()
    CustomHandler.super.new(self, "grant-proxy-oauth")
end

function CustomHandler:access(config)
    if kong.client.get_consumer() and kong.client.get_credential() then
        -- already authenticated through global session plugin
        return
    end

    CustomHandler.super.access(self)
    local error_message = kong.request.get_query_arg("error_description")
    if error_message then
        return kong.response.error(403, error_message)
    end

    local access_token = kong.request.get_query_arg("access_token")
    if not access_token then
        local referrer = kong.request.get_header("referrer")
        if referrer then
            local rb_cookie = "GrantReferrer=" .. referrer .. "; path=/;Max-Age=120"
            kong.response.set_header("Set-Cookie", rb_cookie)
        end
        return
    end

    local ok, err = do_authentication(config)
    if err then
        return kong.response.error(err.status, err.message, err.headers)
    end

    local referrer = ngx.var.cookie_GrantReferrer
    if referrer then
        return ngx.redirect(referrer)
    end

    return ngx.redirect(kong.request.get_path())
end

function do_authentication(config)
    local username = kong.request.get_query_arg("profile[email]")
    if not username or username == "" then
        return nil, {status = 401, message = "Email missing in provider callback"}
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
                local apikey = ngx.encode_base64(credential.key)
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

    local consumer_groups, err = groups.get_consumer_groups(consumer.id)
    if err then
        kong.log.err(err)
        return nil, {status = 500, message = err}
    end

    kong.client.authenticate(consumer, credential)
    ngx.ctx.authenticated_groups = consumer_groups
    return true
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
