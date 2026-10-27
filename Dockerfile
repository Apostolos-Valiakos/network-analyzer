# ── Stage 1: Build ─────────────────────────────────────────────────────────
FROM node:18-alpine AS builder

WORKDIR /app

# Copy manifests first for layer-cache efficiency
COPY package*.json ./
RUN npm install

# Copy source (node_modules excluded via .dockerignore)
COPY . .

# API_BASE_URL and WS_URL are inlined into the webpack bundle by nuxt.config.js
# at build time (SPA/static mode).  Override from docker-compose build.args or
# docker build --build-arg API_BASE_URL=http://your-server:5555
ARG API_BASE_URL=http://localhost:5555
ARG WS_URL=ws://localhost:5002
ENV API_BASE_URL=$API_BASE_URL
ENV WS_URL=$WS_URL

RUN npm run generate

# ── Stage 2: Serve ─────────────────────────────────────────────────────────
FROM nginx:stable-alpine

# Re-declared: build ARGs don't carry across stages. Same values as above —
# docker-compose.yml passes them once as shared build.args for the whole
# multi-stage build.
ARG API_BASE_URL=http://localhost:5555
ARG WS_URL=ws://localhost:5002
# Available as real container env vars at RUNTIME (not just baked into the
# JS bundle) so nginx's CSP can be templated from the same values — see
# nginx.conf.template and nginx-compute-ws-url.envsh. Without this, the CSP's
# connect-src would need a deployment-specific IP hardcoded by hand on every
# new deployment (this was exactly the bug the templating below fixes).
ENV API_BASE_URL=$API_BASE_URL
ENV WS_URL=$WS_URL

COPY --from=builder /app/dist /usr/share/nginx/html
# A *.template file here is envsubst'd into conf.d/ automatically by the
# base image's own entrypoint (docker-entrypoint.d/20-envsubst-on-templates.sh)
# — no custom ENTRYPOINT needed for that part.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
# .envsh, NOT .sh: nginx's entrypoint SOURCES *.envsh files instead of
# running them as a subprocess (needed so the API_BASE_URL_WS this exports
# actually survives to the later envsubst step below — a plain *.sh is
# launched as a throwaway subprocess and loses anything it exports the
# moment it exits). Both *.sh and *.envsh still need the executable bit
# regardless — without it, the entrypoint skips the file entirely
# ("Ignoring ..., not executable"), which fails exactly the same way as
# the .sh-subprocess problem this works around. Verified directly: a
# non-executable .envsh here reproduces the "unknown api_base_url_ws
# variable" error just as reliably as the wrong extension did. Ordered by
# filename, 05 < 20, so it runs before envsubst.
COPY nginx-compute-ws-url.envsh /docker-entrypoint.d/05-compute-ws-url.envsh
RUN chmod +x /docker-entrypoint.d/05-compute-ws-url.envsh

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
