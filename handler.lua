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
    local access_token = kong.request.get_query_arg("access_token")

    if access_token then
        local ok, err = do_authentication(config)
        if ok then
            local redirect_back = ngx.var.cookie_EOAuthRedirectBack
            return ngx.redirect(redirect_back)
        else
            if config.anonymous then
                local consumer_cache_key = kong.db.consumers:cache_key(config.anonymous)
                local consumer, err = kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, config.anonymous, true)
                if err then
                    return error(err)
                end
                set_consumer(consumer)
            else
                return kong.response.error(err.status, err.message, err.headers)
            end
        end
    else
        return redirect_to_auth(config)
    end
end

function do_authentication(config)
    local username = kong.request.get_query_arg("profile[email]")
    if not username then
        return nil, {status = 401, message = "No email or user has denied access."}
    end

    local cache = kong.cache
    local consumer_cache_key = kong.db.consumers:cache_key(username)
    local consumer, err = cache:get(consumer_cache_key, nil, load_consumer_by_username, username)
    if err then
        kong.log.err(err)
        return nil, {status = 500, message = err}
    end

    local acls_cache_key = kong.db.acls:cache_key(consumer.id)
    local groups, err = cache:get(acls_cache_key, nil, load_groups_into_memory, {id = consumer.id})
    if err then
        kong.log.err(err)
        return nil, {status = 500, message = err}
    end

    local credential_cache_key = kong.db.keyauth_credentials:cache_key(consumer.id)
    local credential, err = cache:get(credential_cache_key, nil, load_credential, {id = consumer.id})
    if err then
        kong.log.err(err)
        return nil, {status = 500, message = err}
    end

    set_consumer(consumer, credential, groups)
    return true
end

function redirect_to_auth(config)
    -- TODO not on ajax, anonymous consumer, loop providers?
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

function set_consumer(consumer, credential, groups)
    kong.client.authenticate(consumer, credential)

    local set_header = kong.service.request.set_header
    local clear_header = kong.service.request.clear_header

    if consumer and consumer.id then
        set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    else
        clear_header(constants.HEADERS.CONSUMER_ID)
    end

    if consumer and consumer.custom_id then
        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    else
        clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer and consumer.username then
        set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
    else
        clear_header(constants.HEADERS.CONSUMER_USERNAME)
    end

    if credential then
        if credential.username then
            set_header(constants.HEADERS.CREDENTIAL_USERNAME, credential.username)
        else
            clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
        end

        clear_header(constants.HEADERS.ANONYMOUS)

        -- apikey = ngx.encode_base64(credential....)
        -- TODO set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, apikey)

    else
        clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
        set_header(constants.HEADERS.ANONYMOUS, true)
    end

    if groups then
        set_header(constants.HEADERS.AUTHENTICATED_GROUPS, concat(groups, ", "))
        ngx.ctx.authenticated_groups = groups
    else
        clear_header(constants.HEADERS.AUTHENTICATED_GROUPS)
    end
end

function load_consumer_by_username(consumer_username)
    local consumer, err = kong.db.consumers:select_by_username(consumer_username)

    if not consumer then
        if err then
            return nil, err
        else
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

function load_credential(consumer_pk)
    for row, err in kong.db.keyauth_credentials:each_for_consumer(consumer_pk) do
        if err then
            return nil, err
        end
        return row
    end
end

return CustomHandler
