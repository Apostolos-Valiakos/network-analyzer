# Open5GS WebUI (subscriber management), same release as the core.
#
# Build (context = deploy/k8s/images):
#   docker build -f open5gs-webui/Dockerfile -t open5gs-webui:2.7.6 .
FROM node:20-bookworm-slim

ARG OPEN5GS_VERSION=v2.7.6

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${OPEN5GS_VERSION}" https://github.com/open5gs/open5gs /src/open5gs \
    && mv /src/open5gs/webui /webui \
    && rm -rf /src/open5gs

WORKDIR /webui
RUN npm ci && npm run build

# DB_URI is set by the Deployment. HOSTNAME makes the server listen on the pod
# IP instead of localhost.
ENV NODE_ENV=production HOSTNAME=0.0.0.0 PORT=9999
EXPOSE 9999
CMD ["npm", "run", "start"]
