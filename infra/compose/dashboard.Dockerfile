FROM node:22.17.0-alpine3.22 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22.17.0-alpine3.22
WORKDIR /app
COPY --from=build /app/dist/client ./dist/client
COPY infra/compose/dashboard-server.mjs ./dashboard-server.mjs
USER node
CMD ["node", "dashboard-server.mjs"]
