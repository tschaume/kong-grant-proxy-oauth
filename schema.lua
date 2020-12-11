-- Copyright 2020 Patrick Huck
local typedefs = require "kong.db.schema.typedefs"

return {
    name = "grant-proxy-oauth",
    fields = {
        {consumer = typedefs.no_consumer},
        {config = {
            type = "record",
            fields = {
                {secret = {type = "string", required = true}},
                {anonymous = {type = "string", required = true, default = "anonymous"}},
                {environment = {
                    type = "string", required = true, default = "production",
                    one_of = {"production", "development"},
                }},
            },
        }},
    },
}
