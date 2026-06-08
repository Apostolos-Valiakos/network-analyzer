# ── Stage 1: Build ─────────────────────────────────────────────────────────
FROM node:18-alpine AS builder

WORKDIR /app

# Copy manifests first for layer-cache efficiency
COPY package*.json ./
RUN npm ci --prefer-offline

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

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
