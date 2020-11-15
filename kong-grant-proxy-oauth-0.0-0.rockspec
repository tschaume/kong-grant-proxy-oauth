package = "kong-grant-proxy-oauth"
version = "0.0-0"
source = {
  url = "https://github.com/tschaume/kong-grant-proxy-oauth.git"
}
description = {
  summary = "Kong plugin for authentication against Grant OAuth Proxy Server",
  license = "Apache 2.0"
}
dependencies = {
  "lua >= 5.1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.grant-proxy-oauth.handler"] = "handler.lua",
    ["kong.plugins.grant-proxy-oauth.schema"] = "schema.lua"
  }
}
