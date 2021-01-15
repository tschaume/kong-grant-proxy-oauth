FROM kong:2.3.0-alpine

USER root
ENV LUA_PATH /usr/local/share/lua/5.1/?.lua;;

RUN apk add --no-cache git
RUN luarocks install kong-response-size-limiting
RUN luarocks install kong-log-google
RUN git clone https://github.com/stone-payments/kong-plugin-url-rewrite.git && \
    cd kong-plugin-url-rewrite && luarocks make
RUN git clone https://github.com/tschaume/kong-plugin-redirect.git && \
    cd kong-plugin-redirect && luarocks make

COPY . /grant-proxy-oauth
RUN cd /grant-proxy-oauth && luarocks make

USER kong

#CMD ["kong", "migrations", "bootstrap"]
CMD ["sh", "-c", "kong migrations up && kong migrations finish && kong start"]
