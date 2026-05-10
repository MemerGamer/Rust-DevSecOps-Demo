FROM rust:1.82
WORKDIR /app
COPY . .
RUN cargo build --release
EXPOSE 22
CMD ["./target/release/tictactoe"]
