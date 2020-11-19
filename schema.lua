-- Copyright 2020 Patrick Huck
local typedefs = require "kong.db.schema.typedefs"
local utils = require "kong.tools.utils"
local encode_base64 = ngx.encode_base64
local char = string.char
local rand = math.random

--- kong.utils.random_string with 32 bytes instead
-- @returns random string of length 44
local function random_string()
    return encode_base64(utils.get_rand_bytes(32, true))
    :gsub("/", char(rand(48, 57)))  -- 0 - 10
    :gsub("+", char(rand(65, 90)))  -- A - Z
    :gsub("=", char(rand(97, 122))) -- a - z
end

return {
    name = "grant-proxy-oauth",
    fields = {
        {consumer = typedefs.no_consumer},
        {config = {
            type = "record",
            fields = {
                {host = typedefs.url {default = "http://localhost:3000", required = true}},
                {secret = {type = "string", required = true, default = random_string()}},
                {anonymous = {type = "string", uuid = true, required = true}},
                {twitter = {
                    type = "record",
                    fields = {
                        {key = {type = "string"}},
                        {secret = {type = "string"}}
                    }
                }},
            },
        }},
    },
}
