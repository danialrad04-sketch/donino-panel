# syntax=docker/dockerfile:1
FROM debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN --mount=type=secret,id=system_ca,required=true \
    apt-get -o Acquire::https::CaInfo=/run/secrets/system_ca update && \
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CaInfo=/run/secrets/system_ca install -y --no-install-recommends python3 python3-venv ca-certificates iproute2 openvpn nftables curl procps && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements.lock /requirements/
RUN --mount=type=secret,id=system_ca,required=true \
    python3 -m venv /venv && PIP_CERT=/run/secrets/system_ca /venv/bin/pip install -r /requirements/requirements.txt
COPY app /source/app
COPY agent /source/agent
COPY ops /source/ops
COPY tests/openvpn/network.py /source/network.py
ENV PYTHONPATH=/source
WORKDIR /source
CMD ["/venv/bin/python", "/source/network.py"]
