FROM rancher/agent-base:v0.3.0
RUN apt-get update && \
    apt-get install -y ipset && \
    rm -rf /var/lib/apt/lists/*
COPY network-policy-manager /usr/bin/
CMD ["network-policy-manager"]
