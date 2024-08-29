# Use the official Rust image as a builder
FROM rust:1.72 as builder

# Create a new directory for the application source code
WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files to the working directory
COPY Cargo.toml Cargo.lock ./

# Fetch the dependencies for the project. This layer will be cached unless the dependencies change
RUN cargo fetch

# Copy the rest of the source code to the working directory
COPY src ./src

# Build the application
RUN cargo build --release

# Create a new, minimal image for running the application
FROM debian:buster-slim

# Install necessary dependencies for running Rust applications
RUN apt-get update && \
    apt-get install -y libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a directory for the application
WORKDIR /usr/src/app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/execution-service .

# Expose the port on which the service will run
EXPOSE 3030

# Run the application
CMD ["./execution-service"]
