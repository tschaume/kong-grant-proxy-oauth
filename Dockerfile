FROM kong:1.5.1-alpine

USER root
ENV LUA_PATH /usr/local/share/lua/5.1/?.lua;/usr/local/kong-oidc/?.lua;/usr/local/kong-oidc-consumer/?.lua;;

RUN apk add --no-cache git openssl-dev gcc musl-dev
RUN luarocks install kong-response-size-limiting
RUN luarocks install kong-log-google
RUN luarocks install https://raw.githubusercontent.com/tschaume/kong-oidc/release/kong-oidc-1.1.0-0.rockspec
RUN luarocks install https://raw.githubusercontent.com/tschaume/kong-oidc-consumer/release/kong-oidc-consumer-0.0.1-1.rockspec

COPY . /grant-proxy-oauth
RUN cd /grant-proxy-oauth && luarocks make

USER kong

#CMD ["kong", "migrations", "bootstrap"]
CMD ["sh", "-c", "kong migrations up && kong migrations finish && kong start"]
