# =============================================================================
# Open Terminal + Framework Workbench Image
#
# Network-isolated workbench: framework code and all CLI tools are baked in,
# but the entrypoint iptables firewall blocks all outbound except loopback,
# the Docker subnet (ChromaDB), and Ollama.  The agent cannot bypass the
# framework scope layer by shelling out to nmap/masscan/amass directly.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder — Python venv + Go tools + radare2 in an isolated layer
# ---------------------------------------------------------------------------
FROM ghcr.io/open-webui/open-terminal:slim AS builder
USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc g++ \
        libffi-dev libssl-dev libxml2-dev libxslt1-dev libpcap-dev \
        golang-go git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m ensurepip --upgrade
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/framework-venv \
    && /opt/framework-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/framework-venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
    && /opt/framework-venv/bin/pip install --no-cache-dir \
        chromadb==1.5.9 \
        pydantic-ai==2.35.0 \
    && /opt/framework-venv/bin/pip install --no-cache-dir --no-deps --force-reinstall \
        mcp==1.29.0 mcp-types==2.0.0

# Go CLI tools: ffuf + amass
RUN mkdir -p /opt/go-tools \
    && GOPATH=/tmp/gopath go install github.com/ffuf/ffuf/v2@latest \
    && cp /tmp/gopath/bin/ffuf /opt/go-tools/
RUN GOPATH=/tmp/gopath go install github.com/owasp-amass/amass/v4/...@latest \
    && cp /tmp/gopath/bin/amass /opt/go-tools/ || echo "amass build failed (non-fatal)"

# radare2 from source (builder has gcc)
RUN mkdir -p /opt/r2 \
    && git clone --depth 1 https://github.com/radareorg/radare2 /tmp/r2 \
    && cd /tmp/r2 && ./configure --prefix=/opt/r2 \
    && make -j$(nproc) && make install \
    && rm -rf /tmp/r2 || echo "radare2 build failed (non-fatal)"

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM ghcr.io/open-webui/open-terminal:slim
USER root

# Apt-available security tools + perl (searchsploit is a Perl script)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        hydra \
        sqlmap \
        sqlite3 \
        unzip \
        file \
        iputils-ping \
        perl \
        git \
    && rm -rf /var/lib/apt/lists/*

# searchsploit (exploitdb) — clone DB + symlink the Perl script
RUN git clone --depth 1 https://github.com/offensive-security/exploitdb.git /opt/exploitdb \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Go-built binaries from builder
COPY --from=builder /opt/go-tools/ /usr/local/bin/
RUN chmod +x /usr/local/bin/ffuf /usr/local/bin/amass 2>/dev/null || true

# radare2 from builder (if it built)
COPY --from=builder /opt/r2/ /usr/local/
RUN ldconfig 2>/dev/null || true

COPY --from=builder /opt/framework-venv /opt/framework-venv

COPY . /opt/framework/
RUN chown -R user:user /opt/framework

COPY dockered/entrypoint.sh /app/custom-entrypoint.sh
RUN chmod +x /app/custom-entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/usr/bin/tini", "--", "/app/custom-entrypoint.sh"]
CMD ["run"]
