FROM kong:2.8.4-alpine

USER root
ARG VERSION
ENV LUA_PATH=/usr/local/share/lua/5.1/?.lua;; \
  DD_SERVICE=kong \
  DD_ENV=prod \
  DD_VERSION=$VERSION \
  DD_PROFILING_ENABLED=true \
  DD_LOGS_INJECTION=true

RUN apk add git lua5.4 lua5.4-dev make
RUN git clone --depth 1 https://github.com/luarocks/luarocks
RUN cd luarocks && ./configure --prefix=/usr/local/openresty/luajit --lua-version=5.4 && make && make install
RUN luarocks config lua_version 5.1

RUN apk add --no-cache wget curl httpie && \
  wget -q https://raw.githubusercontent.com/tschaume/kong/feat/persistent-cookie/kong/plugins/session/schema.lua && \
  mv schema.lua /usr/local/share/lua/5.1/kong/plugins/session/ && \
  wget -q https://raw.githubusercontent.com/tschaume/kong/feat/persistent-cookie/kong/plugins/session/session.lua && \
  mv session.lua /usr/local/share/lua/5.1/kong/plugins/session/ && \
  chmod -R a+r /usr/local/share/lua/5.1/kong/plugins/session

WORKDIR grant-proxy-oauth
COPY handler.lua .
COPY schema.lua .
COPY kong-grant-proxy-oauth-0.0-0.rockspec .
#RUN luarocks install penlight
RUN /usr/local/openresty/luajit/bin/luarocks install --tree /usr/local lua-resty-cookie
RUN /usr/local/openresty/luajit/bin/luarocks --tree /usr/local/ make

COPY start.sh .
RUN chmod a+rx start.sh

LABEL com.datadoghq.ad.check_names='["kong"]'
LABEL com.datadoghq.ad.init_configs='[{}]'
LABEL com.datadoghq.ad.instances='[{"openmetrics_endpoint": "http://%%host%%:8001/metrics"}]'
LABEL com.datadoghq.ad.logs='[{"source": "kong", "service": "kong", "log_processing_rules": [{"type": "exclude_at_match", "name": "exclude_logs", "pattern": "(?:queryDns)|(?:\"status_code\":\\s20)"}]}]'

COPY custom-nginx.template .
RUN chmod a+rx custom-nginx.template

USER kong
CMD ./start.sh
