FROM rust:1.97
WORKDIR /app
COPY . .
RUN cargo build --release
# INTENTIONAL: EXPOSE 22 and no USER/HEALTHCHECK instruction. Left
# unfixed on purpose so the config check (Checkov) fails and the deploy
# gate blocks deployment; see README.md. Do not fix.
EXPOSE 22
CMD ["./target/release/tictactoe"]
