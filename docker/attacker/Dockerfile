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

WORKDIR /opt

RUN mkdir -p /opt/wordlists && printf 'admin\npassword\n123456\nelliot\nmrrobot\nER28-0652\nabcdefghijklmnopqrstuvwxyz\n' > /opt/wordlists/mrrobot.txt

CMD ["sleep", "infinity"]
