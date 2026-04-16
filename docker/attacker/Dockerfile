FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    sqlmap \
    gobuster \
    wpscan \
    john \
    netcat-traditional \
    curl \
    wget \
    git \
    perl \
    libwhisker2-perl \
    libjson-perl \
    libxml-writer-perl \
    net-tools \
    iputils-ping \
    iproute2 \
    dnsutils \
    ssh \
    sshpass \
    python3 \
    procps \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

RUN git clone --depth 1 https://github.com/v0re/dirb.git /opt/dirb-src && \
    mkdir -p /usr/share/wordlists/dirb && \
    cp /opt/dirb-src/wordlists/common.txt /usr/share/wordlists/dirb/common.txt && \
    cp /opt/dirb-src/wordlists/big.txt /usr/share/wordlists/dirb/big.txt 2>/dev/null || true && \
    rm -rf /opt/dirb-src

WORKDIR /opt

RUN mkdir -p /opt/wordlists

CMD ["sleep", "infinity"]
