-- Copyright 2020 Patrick Huck

local resty_session = require "resty.session"
local constants = require "kong.constants"
local BasePlugin = require "kong.plugins.base_plugin"
local kong_utils = require "kong.tools.utils"
local acl_groups = require "kong.plugins.acl.groups"
-- local openssl = require('openssl')

local ngx = ngx
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

    -- check if already authenticated through global session plugin
    if config.anonymous and consumer and credential then
        local consumer_groups, err = acl_groups.get_consumer_groups(consumer.id)
        if err then
            return kong.response.exit(500, "failed to retrieve groups for " .. consumer.username)
        end
        set_consumer(consumer, credential, consumer_groups)
        kong.log.notice(consumer.username .. " - session authenticated")
        return
    end

    -- set up session and init with grant cookie
    local opts = {name = "grant_session", storage = "redis", secret = config.secret}
    opts.redis = {host = config.redis}
    local session = resty_session.new(opts)
    local cookie = resty_session.get_cookie(session)
    if not cookie then
        kong.log.info("anonymous - grant cookie missing")
        return do_authentication(session, nil, config.anonymous)
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
        kong.log.notice("anonymous - failed to retrieve grant session data")
        return do_authentication(session, nil, config.anonymous)
    end

    -- serialize session data
    data, err = session.serializer.deserialize(data)
    if err then
        kong.log.notice("anonymous - failed to deserialize grant session data")
        return do_authentication(session, nil, config.anonymous)
    end

    -- check if oauth cycle completed
    if type(data.grant.response) ~= "table" then
        kong.log.notice("anonymous - grant oauth cycle not completed yet")
        return do_authentication(session, nil, config.anonymous)
    end

    -- get username <provider>:<email>
    -- different accounts for different providers to avoid potential hijacking
    local provider = data.grant.provider
    local email = data.grant.response.profile.email
    local username = provider .. ":" .. email

    -- authenticate user
    do_authentication(session, username, config.anonymous)

    -- destroy grant session
    if kong.client.get_credential() then
        local ok, err = session.storage:destroy(session_id)
        if err then
            return kong.response.exit(500, err)
        end
        if not ok then
            return kong.response.exit(500, "failed to destroy " .. session_id)
        end
    end
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

function do_authentication(session, consumerid_or_username, anonymous)
    -- load consumer
    local consumer
    if consumerid_or_username then
        consumer = kong.client.load_consumer(consumerid_or_username, true)
        if not consumer then
            -- consumer not created by grant server yet
            kong.log.notice("anonymous - user not created yet: " .. consumerid_or_username)
        end
    end

    -- destroy resty_session
    session.data      = {}
    session.present   = nil
    session.opened    = nil
    session.started   = nil
    session.closed    = true
    session.destroyed = true

    -- load and authenticate anonymous consumer if needed
    if not consumer then
        consumer = kong.client.load_consumer(anonymous, true)
        return set_consumer(consumer)
    end

    -- authenticate user (incl. credential and groups)
    local ok, err = authenticate(consumer)
    if err then
        return kong.response.exit(500, err)
    end
    if not ok then
        return kong.response.exit(500, "failed to authenticate " .. consumer.username)
    end

    kong.log.notice(consumerid_or_username .. " authenticated")
end

function authenticate(consumer)
    local cache_key = kong.db.keyauth_credentials:cache_key(consumer.id)
    local credential, err = kong.cache:get(cache_key, nil, load_credential, {id = consumer.id})
    if err then
        return nil, err
    end

    local consumer_groups, err = acl_groups.get_consumer_groups(consumer.id)
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
        set_header(constants.HEADERS.AUTHENTICATED_GROUPS, table.concat(groups, ", "))
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
