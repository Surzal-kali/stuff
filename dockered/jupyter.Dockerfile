# =============================================================================
# JupyterLab workbench image — tool nursery over the framework.
#
# Extends jupyter/minimal-notebook (jovyan, UID 1000 — matches host surzal so
# the bind-mounted ../framework tree is writable). Bakes native build deps
# (libpcap/libxslt/libssl + gcc) and the framework requirements once.
#
# NETWORK POSTURE (2026-09-17, user decision "C"): no iptables lockdown and
# no root entrypoint — the container runs as jovyan with the stock notebook
# entrypoint. The old firewall mirrored open-terminal's cage; it was removed
# with the cage itself (scope stays in-process; the nursery can now be
# proxied and reach the framework gateway on the subnet like any other
# service). The nursery is localhost-only at the port level (compose binds
# 127.0.0.1:8888), JUPYTER_TOKEN still gates access.
# =============================================================================

FROM jupyter/minimal-notebook:latest

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc g++ \
        libffi-dev libssl-dev libxml2-dev libxslt1-dev libpcap-dev \
        git \
    && apt-get clean

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Stock notebook entrypoint as jovyan — no custom entrypoint, no lockdown.
USER ${NB_UID:-1000}

WORKDIR /home/jovyan/framework
