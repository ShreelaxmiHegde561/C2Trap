# Zeek Monitor for C2Trap
FROM zeek/zeek:latest

# Install utilities for log processing and network detection
RUN apt-get update && apt-get install -y \
    jq \
    curl \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install JA3 package for TLS fingerprinting (use yes to auto-confirm prompts)
RUN yes | zkg autoconfig && zkg install --force ja3

# Set working directory
WORKDIR /usr/local/zeek

# Copy configuration files
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Create log directories
RUN mkdir -p /usr/local/zeek/logs /app/logs/zeek

# Use startup script for dynamic interface detection
CMD ["/start.sh"]
