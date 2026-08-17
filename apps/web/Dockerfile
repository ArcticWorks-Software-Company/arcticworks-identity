FROM node:26-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/web/package.json apps/web/package.json
COPY packages/identity-sdk/package.json packages/identity-sdk/package.json
COPY examples/continuity-mock/package.json examples/continuity-mock/package.json
COPY e2e/package.json e2e/package.json
RUN npm ci --workspace apps/web --include-workspace-root
COPY apps/web apps/web
RUN npm run build:web

FROM node:26-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=3000
COPY --from=build --chown=node:node /app/apps/web/build ./build
EXPOSE 3000
USER node
CMD ["node", "build"]
