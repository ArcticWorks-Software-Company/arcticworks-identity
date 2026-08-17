FROM rust:1.97-bookworm AS build
WORKDIR /app
COPY apps/api .
RUN cargo build --release --bin api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/api /usr/local/bin/api
EXPOSE 8080
USER 10001
CMD ["api"]
