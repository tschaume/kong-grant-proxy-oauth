-- Copyright 2020 Patrick Huck

local BasePlugin = require "kong.plugins.base_plugin"
local kong_utils = require "kong.tools.utils"
local groups = require "kong.plugins.acl.groups"
local twitter = require("twitter")

local kong = kong
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
    if err then
        return kong.response.error(err.status, err.message, err.headers)
    end

    local redirect_back = ngx.var.cookie_EOAuthRedirectBack
    return ngx.redirect(redirect_back)
end

function do_authentication(config)
    local username = kong.request.get_query_arg("profile[email]")
    if not username or username == "" then
        local provider = ngx.ctx.router_matches.uri_captures.provider
        if provider == "twitter" and config.twitter.key and config.twitter.secret then
            local oauth_token = kong.request.get_query_arg("raw[oauth_token]")
            local oauth_token_secret = kong.request.get_query_arg("raw[oauth_token_secret]")
            local user_client = twitter.Twitter({
                access_token = oauth_token,
                access_token_secret = oauth_token_secret,
                consumer_key = config.twitter.key,
                consumer_secret = config.twitter.secret
            })
            username = twitter_email(user_client)
            kong.log.warn("USERNAME", username)
            if not username then
                return nil, {status = 401, message = "Please add an e-mail address to your Twitter profile"}
            end
        else
            return nil, {status = 401, message = "Email missing in provider callback"}
        end
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

function redirect_to_auth(config)
    local rb_cookie = "EOAuthRedirectBack=" .. ngx.var.request_uri .. "; path=/;Max-Age=120"
    kong.response.set_header("Set-Cookie", rb_cookie)
    local provider = ngx.ctx.router_matches.uri_captures.provider
    if not provider then
        return kong.response.error(500, "Invalid route: provider capture group missing.")
    end

    local connect = config.host .. "/connect/" .. provider
    local scheme = kong.request.get_scheme()
    local host = kong.request.get_host()
    local port = kong.request.get_port()
    local path = kong.request.get_path_with_query()
    local callback = scheme .. "://" .. host .. ":" .. port .. path
    return ngx.redirect(connect .. "?callback=" .. callback)
end

function twitter_email(client)
    local opts = {skip_status = true, include_email = true, include_entities = false}
    kong.log.warn("SEND TWITTER REQUEST")
    resp = client:_request("GET", "/1.1/account/verify_credentials.json", opts)
    kong.log.warn("RESPONSE", resp)
    result = client:_handle_error(result)
    if not result then
        return kong.response.error(500, "Failed to retrieve email from Twitter")
    end
    kong.log.warn(result)
    return result.email
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
