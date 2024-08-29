FROM rust:slim-buster AS builder

RUN apt-get update && \
  apt-get install -y pkg-config make g++ libssl-dev cmake libmariadb-dev-compat zlib1g && \
  rustup target add x86_64-unknown-linux-gnu

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./

RUN cargo fetch

COPY src ./src

# Build the application
RUN cargo build --release --bin task-performer

# Prod stage, removing the Rust toolchain
FROM gcr.io/distroless/cc

# RUN apt-get update \
#     apt-get install libssl

COPY --from=builder /usr/src/app/target/release/task-performer .

# Run the application
CMD ["./task-performer"]
