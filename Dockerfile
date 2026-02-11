# Stage 1: Builder
# This stage compiles the AiDA IDA Pro plugin.
FROM ubuntu:22.04 AS builder

LABEL description="Build container for the AiDA IDA Pro plugin"

# Install build dependencies
RUN apt-get update && \
    apt-get install -y build-essential git wget tar libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Download and install CMake 3.27.1
RUN wget -qO- "https://cmake.org/files/v3.27/cmake-3.27.1-linux-x86_64.tar.gz" | tar --strip-components=1 -xz -C /usr/local

# Set the working directory
WORKDIR /app

# Clone the IDA SDK from the official GitHub repository.
RUN git clone --depth 1 https://github.com/HexRaysSA/ida-sdk.git /idasdk
ENV IDASDK /idasdk

# Copy the project source code into the container
COPY . .

# check if submodules are not initialized, then tell user to run "git submodule update --init --recursive"
RUN if [ ! -d "cmake/ida-cmake" ]; then echo "Submodules are not initialized. Please run 'git submodule update --init --recursive' to initialize them."; exit 1; fi


# Configure the CMake project
RUN cmake -B build


# Build the project in Release configuration
RUN cmake --build build --config Release

# Create a directory to store the final plugin and move the compiled artifact there.
# This provides a known location to copy from in the next stage.
RUN mkdir /plugin && find /idasdk/src/bin/plugins/ -type f -name '*.so' -exec mv {} /plugin/ \;

# ---

# Stage 2: Final Image
# This stage contains only the compiled plugin for easy extraction.
FROM alpine:3.18

# Copy the compiled plugin from the known location in the builder stage.
# The final image will contain only the plugin artifact.
COPY --from=builder /plugin/* /
