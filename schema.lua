-- Copyright 2020 Patrick Huck

local typedefs = require "kong.db.schema.typedefs"

return {
    name = "grant-proxy-oauth",
    fields = {
        {consumer = typedefs.no_consumer},
        {config = {
            type = "record",
            fields = {
                {host = typedefs.url {default = "http://localhost:3000"}},
                {provider = {type = "string", default = "phantauth"}},
                {secret = {type = "string", required = true}},
                {auth_token_expire_time = {type = "integer", default = 259200}},
            },
        }},
    },
}
