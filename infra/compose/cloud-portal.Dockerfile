FROM node:22.17.0-alpine3.22
WORKDIR /app
COPY apps/cloud-portal /app/portal
USER node
ENV CLOUD_PORTAL_ROOT=/app/portal PORT=4180
CMD ["node", "/app/portal/server.mjs"]
