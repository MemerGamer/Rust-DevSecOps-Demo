FROM rust:1.82 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN groupadd -r app && useradd -r -g app -u 1001 app
WORKDIR /app
COPY --from=builder /app/target/release/tictactoe .
USER app
HEALTHCHECK NONE
CMD ["./tictactoe"]
