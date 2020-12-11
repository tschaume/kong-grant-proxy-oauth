-- Copyright 2020 Patrick Huck

local resty_session = require "resty.session"
local constants = require "kong.constants"
local BasePlugin = require "kong.plugins.base_plugin"
local kong_utils = require "kong.tools.utils"
local groups = require "kong.plugins.acl.groups"
-- local openssl = require('openssl')

local kong = kong
local CustomHandler = BasePlugin:extend()

CustomHandler.VERSION  = "0.0-0"
CustomHandler.PRIORITY = 1004

function CustomHandler:new()
    CustomHandler.super.new(self, "grant-proxy-oauth")
end

function CustomHandler:access(config)
    CustomHandler.super.access(self)
    local consumer = kong.client.get_consumer()
    local credential = kong.client.get_credential()

    if config.anonymous and consumer and credential then
        -- already authenticated through global session plugin
        return
    end

    -- get username (provider:email) from grant session in redis
    -- different accounts for different providers to avoid potential hijacking
    local opts = {name = "grant_session", storage = "redis", secret = config.secret}
    if config.environment == "development" then
        opts.redis = {host = "redis"}
    end
    local session = resty_session.new(opts)
    local cookie = resty_session.get_cookie(session)
    if not cookie then
        local destroyed = session.destroy()
        if not destroyed then
            return kong.response.exit(500, "resty session not destroyed")
        end
        local ok, err = do_authentication(config.anonymous, true)
        if err then
            return kong.response.exit(err.status, err.message, err.headers)
        end
        return
    end

    -- URL-unescape cookie and check prefix
    cookie = ngx.unescape_uri(cookie)
    local prefix = string.sub(cookie, 1, 2)
    if prefix ~= "s:" then
        return kong.response.exit(500, "wrong cookie prefix")
    end

    -- get session ID
    local sep_idx = string.find(cookie, '.', 3, true)
    local session_id = string.sub(cookie, 3, sep_idx-1)

    -- TODO check signature
    -- local signed, err = sign(session_id, config.secret)
    -- if err then
    --     return kong.response.exit(500, err)
    -- end
    -- if session_id ~= signed then
    --     return kong.response.exit(500, "invalid signature")
    -- end

    -- retrieve session data
    local data, err = session.storage:open(session_id)
    if err or not data then
        local ok, err = do_authentication(config.anonymous, true)
        if err then
            return kong.response.exit(err.status, err.message, err.headers)
        end
        return
    end

    data, err = session.serializer.deserialize(data)
    if err then
        return kong.response.exit(500, err)
    end

    if type(data.grant.response) ~= "table" then
        local ok, err = do_authentication(config.anonymous, true)
        if err then
            return kong.response.exit(err.status, err.message, err.headers)
        end
        return
    end

    -- set username
    local provider = data.grant.provider
    local email = data.grant.response.profile.email
    local username = provider .. ":" .. email

    local ok, err = do_authentication(username)
    if err then
        return kong.response.exit(err.status, err.message, err.headers)
    end

    -- destroy resty_session and grant session
    local destroyed = session.destroy()
    if not destroyed then
        return kong.response.exit(500, "resty session not destroyed")
    end

    local ok, err = session.storage:destroy(session_id)
    if not ok or err then
        return kong.response.exit(500, err)
    end

    kong.log.warn(username .. " authenticated")
end

-- see https://github.com/tj/node-cookie-signature/blob/master/index.js
-- function sign(val, secret)
--     local digest, err = openssl.hmac.digest('sha256', val, secret)
--     if err then
--         return nil, err
--     end
--     local encoded, err = openssl.base64(digest)
--     if err then
--         return nil, err
--     end
--     local signature = encoded -- TODO .replace(/\=+$/, '')
--     return val .. "." .. signature
-- end

function do_authentication(consumerid_or_username, anonymous)
    local consumer_cache_key = kong.db.consumers:cache_key(consumerid_or_username)
    local consumer, err = kong.cache:get(
        consumer_cache_key, nil, kong.client.load_consumer, consumerid_or_username, true
    )
    if err then
        kong.log.err(err)
        return nil, {status = 500, message = err}
    end

    local ok, err = authenticate(consumer, anonymous)
    if err then
        kong.log.err(err)
        return nil, {status = 500, message = err}
    end

    return true
end

function authenticate(consumer, anonymous)
    if anonymous then
        return set_consumer(consumer)
    end

    local cache_key = kong.db.keyauth_credentials:cache_key(consumer.id)
    local credential, err = kong.cache:get(cache_key, nil, load_credential, {id = consumer.id})
    if err then
        return nil, err
    end

    local consumer_groups, err = groups.get_consumer_groups(consumer.id)
    if err then
        return nil, err
    end

    return set_consumer(consumer, credential, consumer_groups)
end

function load_credential(consumer_pk)
    for row, err in kong.db.keyauth_credentials:each_for_consumer(consumer_pk) do
        if err then
            return nil, err
        end
        return row
    end
end

function set_consumer(consumer, credential, groups)
    local set_header = kong.service.request.set_header
    local clear_header = kong.service.request.clear_header

    if consumer.id then
        set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    else
        clear_header(constants.HEADERS.CONSUMER_ID)
    end

    if consumer.custom_id then
        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    else
        clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer.username then
        set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
    else
        clear_header(constants.HEADERS.CONSUMER_USERNAME)
    end

    if groups then
        set_header(constants.HEADERS.AUTHENTICATED_GROUPS, concat(groups, ", "))
        ngx.ctx.authenticated_groups = groups
    else
        clear_header(constants.HEADERS.AUTHENTICATED_GROUPS)
    end

    if credential then
        clear_header(constants.HEADERS.ANONYMOUS)
        if constants.HEADERS.CREDENTIAL_IDENTIFIER then
            set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, credential.id)
        end
    else
        set_header(constants.HEADERS.ANONYMOUS, true)
        if constants.HEADERS.CREDENTIAL_IDENTIFIER then
            clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
        end
    end

    kong.client.authenticate(consumer, credential)
    return true
end

return CustomHandler
