# Use a lightweight Debian image
FROM debian:stable-slim

# Install Python and required packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    inotify-tools \
    strace \
    tcpdump \
    bash \
    libcurl4 \
    ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create log directory
RUN mkdir -p /sandbox/logs

# Copy analysis script and set permissions
COPY analysis.sh /usr/local/bin/analysis.sh
RUN chmod +x /usr/local/bin/analysis.sh

# Set working directory
WORKDIR /sandbox

# Copy requirements and all app files
COPY requirements.txt .
COPY . .

# Create venv and install packages there
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Set environment variables to use venv by default
ENV PATH="/opt/venv/bin:$PATH"

# Run the main app
CMD ["python3", "final1.py"]
