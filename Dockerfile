FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY tsconfig*.json ./
COPY src ./src
COPY scripts/build.mjs ./scripts/build.mjs
RUN npm run build && npm prune --omit=dev --ignore-scripts
FROM node:24-alpine
WORKDIR /app
COPY --from=build /app/package*.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/src/account-hub/ui ./src/account-hub/ui
COPY LICENSE NOTICE THIRD_PARTY.md ./
RUN mkdir /state && chown node:node /state
USER node
ENV PORT=8892 HOST=0.0.0.0 NULUNO_ACCESS_STATE=/state/access.sqlite
VOLUME /state
EXPOSE 8892
CMD ["node","dist/server.mjs"]
