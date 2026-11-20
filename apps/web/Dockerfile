# klav.dev: the site and its waitlist (docs/sitio-web.md). No npm
# dependencies: node:http and node:sqlite (Node >= 22.13).
FROM node:22.23.4-alpine3.24

# setpriv (util-linux): the entrypoint drops root after fixing /data, as
# deploy/railway/entrypoint.sh does for klav-server. Busybox's lacks --reuid.
RUN apk add --no-cache setpriv \
    && mkdir -p /data \
    && chown node:node /data \
    && chmod 700 /data

ENV NODE_ENV=production \
    PORT=8080 \
    KLAV_WEB_DB=/data/waitlist.db \
    KLAV_WEB_TRUST_PROXY=1

WORKDIR /app
COPY server.mjs ./
COPY public ./public
COPY entrypoint.sh /usr/local/bin/klav-web-entrypoint

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1
ENTRYPOINT ["/bin/sh", "/usr/local/bin/klav-web-entrypoint"]
