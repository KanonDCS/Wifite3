FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    build-essential \
    libpcap-dev \
    libsqlite3-dev \
    sqlite3 \
    pkg-config \
    libnl-genl-3-dev \
    libssl-dev \
    net-tools \
    iw \
    ethtool \
    usbutils \
    pciutils \
    wireless-tools \
    macchanger \
    tshark \
    aircrack-ng \
    reaver \
    bully \
    hcxdumptool \
    hcxtools \
    hashcat \
    python3-scapy \
    python3-tqdm \
    python3-colorama \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/KanonDCS/Wifite3.git /Wifite3
WORKDIR /Wifite3

RUN pip install -e . --break-system-packages

ENTRYPOINT ["/bin/bash"]
