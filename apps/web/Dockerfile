FROM node:22-alpine AS build
WORKDIR /app
COPY apps/web/package.json package-lock.json* ./
RUN npm install
COPY apps/web .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/build ./build
ENV PORT=3000
EXPOSE 3000
USER node
CMD ["node", "build"]
