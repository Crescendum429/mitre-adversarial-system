FROM kalilinux/kali-rolling

# Toolset alineado con pentesting academico (ref: PentestGPT USENIX 2024,
# PenHeal ACM 2024, Cybench ICLR 2025, OSCP syllabus).
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Recon / scanning
    nmap \
    masscan \
    dnsutils \
    whois \
    fping \
    # Web enum
    gobuster \
    dirb \
    dirsearch \
    whatweb \
    wpscan \
    # Exploitation
    hydra \
    sqlmap \
    john \
    hashcat \
    # SMB / Windows
    enum4linux \
    smbclient \
    smbmap \
    cifs-utils \
    # FTP / SSH
    ftp \
    ssh \
    sshpass \
    # LDAP
    ldap-utils \
    # Metasploit + searchsploit
    metasploit-framework \
    exploitdb \
    # Network tools
    netcat-traditional \
    socat \
    tcpdump \
    curl \
    wget \
    # Exfiltration / encoding
    openssl \
    xxd \
    # Scripting
    python3 \
    python3-pip \
    perl \
    ruby \
    # Misc
    net-tools \
    iputils-ping \
    iproute2 \
    procps \
    git \
    vim-tiny \
    jq \
    libwhisker2-perl \
    libjson-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# Nikto (paquete de Kali suele estar desactualizado; clon oficial)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Wordlists comunes: dirb common.txt/big.txt + rockyou.txt
RUN git clone --depth 1 https://github.com/v0re/dirb.git /opt/dirb-src && \
    mkdir -p /usr/share/wordlists/dirb && \
    cp /opt/dirb-src/wordlists/common.txt /usr/share/wordlists/dirb/common.txt && \
    cp /opt/dirb-src/wordlists/big.txt /usr/share/wordlists/dirb/big.txt 2>/dev/null || true && \
    rm -rf /opt/dirb-src

# rockyou.txt (el wordlist mas referenciado en CTFs y pentesting).
# Si no esta empaquetado en Kali slim, lo descargamos.
RUN mkdir -p /usr/share/wordlists && \
    if [ ! -f /usr/share/wordlists/rockyou.txt ]; then \
        curl -sL https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
            -o /usr/share/wordlists/rockyou.txt || \
        echo "[WARN] rockyou.txt no descargado"; \
    fi

# SecLists (wordlists extensivos, referenciados en todo CTF academico)
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists 2>/dev/null || \
    echo "[WARN] SecLists no descargado (opcional)"

# LinPEAS + WinPEAS: las tools de enumeracion de priv-esc mas usadas en CTFs
RUN mkdir -p /opt/peass && \
    curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \
        -o /opt/peass/linpeas.sh 2>/dev/null && \
    chmod +x /opt/peass/linpeas.sh 2>/dev/null || \
    echo "[WARN] linpeas.sh no descargado"

# pspy (process monitoring sin root, util para cron enumeration)
RUN curl -sL https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 \
    -o /opt/peass/pspy64 2>/dev/null && \
    chmod +x /opt/peass/pspy64 2>/dev/null || \
    echo "[WARN] pspy no descargado"

WORKDIR /opt

# Directorio de wordlists custom que el LLM puede generar en runtime
RUN mkdir -p /opt/wordlists

# Pre-cachea la database de searchsploit para busquedas offline rapidas
RUN searchsploit -u 2>/dev/null || echo "[WARN] searchsploit update fallo (puede intentarse en runtime)"

# Ping tools necesitan NET_RAW capability (se da via docker-compose cap_add)
CMD ["sleep", "infinity"]
