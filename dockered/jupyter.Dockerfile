# =============================================================================
# JupyterLab workbench image — gated tool nursery over the framework.
#
# Extends jupyter/minimal-notebook (jovyan, UID 1000 — matches host surzal so
# the bind-mounted ../framework tree is writable). Bakes native build deps
# (libpcap/libxslt/libssl + gcc) and the framework requirements once, plus
# iptables for the entrypoint network lockdown. Stays root at runtime so the
# entrypoint can apply iptables, then drops to jovyan (no CAP_NET_ADMIN).
# =============================================================================

FROM jupyter/minimal-notebook:latest

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc g++ \
        libffi-dev libssl-dev libxml2-dev libxslt1-dev libpcap-dev \
        iptables gosu \
        git \
    && apt-get clean

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY dockered/jupyter-entrypoint.sh /usr/local/bin/jupyter-entrypoint.sh
RUN chmod +x /usr/local/bin/jupyter-entrypoint.sh

# Runtime stays root so the entrypoint can apply iptables; it drops to jovyan
# before launching the notebook server.
WORKDIR /home/jovyan/framework
