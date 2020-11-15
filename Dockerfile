FROM kong:1.5.1-alpine

USER root
ENV LUA_PATH /usr/local/share/lua/5.1/?.lua;/usr/local/kong-external-oauth/?.lua;;

RUN apk add --no-cache git openssl-dev gcc musl-dev
RUN luarocks install kong-response-size-limiting
RUN luarocks install kong-log-google

COPY . /grant-proxy-oauth
RUN cd /grant-proxy-oauth && luarocks make

USER kong
