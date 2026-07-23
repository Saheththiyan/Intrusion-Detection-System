FROM ubuntu:24.04

# Avoid interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies and Suricata
RUN apt-get update && \
    apt-get install -y software-properties-common jq curl && \
    add-apt-repository ppa:oisf/suricata-stable -y && \
    apt-get update && \
    apt-get install -y suricata && \
    apt-get clean

# Create working directories
RUN mkdir -p /var/log/suricata /pcaps /var/lib/suricata/rules

WORKDIR /suricata

# Default command just prints version — you'll override this at runtime
CMD ["suricata", "--build-info"]