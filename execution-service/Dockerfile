# Build stage, TODO: actix middleware logger einbauen
FROM rust:slim-buster AS builder

RUN apt-get update && \
  # here zlib1g
  apt-get install -y pkg-config make g++ libssl-dev cmake libmariadb-dev-compat zlib1g && \
  rustup target add x86_64-unknown-linux-gnu

# Use the official Rust image as a builder
# FROM rust:1.72 as builder

# Create a new directory for the application source code
WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files to the working directory
COPY Cargo.toml Cargo.lock ./

# Fetch the dependencies for the project. This layer will be cached unless the dependencies change
RUN cargo fetch

# Copy the rest of the source code to the working directory
COPY src ./src

# Build the application
RUN cargo build --release --bin execution-service

# Prod stage, removing the Rust toolchain
FROM gcr.io/distroless/cc

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/execution-service .

# Expose the port on which the service will run
EXPOSE 4003

# Run the application
CMD ["./execution-service"]
