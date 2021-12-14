FROM kong:2.6.0-alpine

USER root
ENV LUA_PATH /usr/local/share/lua/5.1/?.lua;;

RUN apk add --no-cache wget && \
    wget -q https://raw.githubusercontent.com/tschaume/kong/feat/persistent-cookie/kong/plugins/session/schema.lua && \
    mv schema.lua /usr/local/share/lua/5.1/kong/plugins/session/ && \
    wget -q https://raw.githubusercontent.com/tschaume/kong/feat/persistent-cookie/kong/plugins/session/session.lua && \
    mv session.lua /usr/local/share/lua/5.1/kong/plugins/session/ && \
    chmod -R a+r /usr/local/share/lua/5.1/kong/plugins/session

RUN wget -q https://raw.githubusercontent.com/Kong/kong/master/kong/db/schema/metaschema.lua && \
    mv metaschema.lua /usr/local/share/lua/5.1/kong/db/schema/ && \
    chmod a+r /usr/local/share/lua/5.1/kong/db/schema/metaschema.lua

WORKDIR grant-proxy-oauth
COPY handler.lua .
COPY schema.lua .
COPY kong-grant-proxy-oauth-0.0-0.rockspec .
RUN luarocks make

COPY start.sh .
RUN chmod a+rx start.sh

USER kong
CMD ./start.sh
