# Use a lightweight Debian image
FROM debian:stable-slim

# Install required packages including libcurl
RUN apt-get update && apt-get install -y \
    inotify-tools \
    strace \
    tcpdump \
    bash \
    libcurl4 \
    ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create log directory
RUN mkdir -p /sandbox/logs

# Copy analysis script
COPY analysis.sh /usr/local/bin/analysis.sh
RUN chmod +x /usr/local/bin/analysis.sh

# Set working directory
WORKDIR /sandbox

# Set default entrypoint
ENTRYPOINT ["/usr/local/bin/analysis.sh"]
