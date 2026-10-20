FROM debian:13-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-build python3-setuptools python3-wheel python3-venv \
    nftables openssh-server fail2ban python3-systemd unattended-upgrades \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /project
COPY . .
RUN python3 -m build --no-isolation \
    && python3 -m venv /opt/d13dp \
    && /opt/d13dp/bin/pip install --no-index --no-deps dist/*.whl
CMD ["/opt/d13dp/bin/python", "tests/integration/debian13.py"]
