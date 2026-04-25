FROM php:8.1-apache

RUN apt-get update && apt-get install -y \
    nmap \
    john \
    python3 \
    vim-tiny \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash marlinspike

COPY www/ /var/www/html/

RUN set -eux; \
    pass=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12); \
    sed -i "s/__USERNAME__/marlinspike/g" /var/www/html/wp-login.php /var/www/html/wp-admin/theme-editor.php; \
    sed -i "s/__PASSWORD_PLACEHOLDER__/${pass}/g" /var/www/html/wp-login.php; \
    # fsocity.dic: incluye el username (descubrible) y el password (random per-build).
    # Alineado con la estructura del CTF real Mr. Robot 1 (VulnHub) donde fsocity.dic
    # contiene tanto candidatos de usuario como de password.
    echo "marlinspike" >> /var/www/html/fsocity.dic; \
    echo "$pass" >> /var/www/html/fsocity.dic; \
    marl_pass=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 10); \
    marl_md5=$(echo -n "$marl_pass" | md5sum | cut -d' ' -f1); \
    echo "marlinspike:$marl_md5" > /home/marlinspike/password.raw-md5; \
    echo "$marl_pass" >> /var/www/html/fsocity.dic; \
    echo "marlinspike:$marl_pass" | chpasswd

RUN echo "7d03aaa22813a2fa307d574e9baa1e9c" > /home/marlinspike/flag-user.txt && \
    chown marlinspike:marlinspike /home/marlinspike/flag-user.txt /home/marlinspike/password.raw-md5 && \
    chmod 0644 /home/marlinspike/password.raw-md5 && \
    chmod 0600 /home/marlinspike/flag-user.txt && \
    chmod 755 /home/marlinspike

RUN echo "f9e4c8b5a1d263740a7e9f6d5c2b8e43" > /root/flag-root.txt && \
    chmod 600 /root/flag-root.txt

# SUID vim-tiny: permite priv esc via `vim.tiny -c ':py import os; os.system("cat /root/flag-root.txt")'`
# o `vim -c ':!/bin/sh'` si vim es completo. Simula sudo-vim misconfig clasico.
RUN chmod u+s /usr/bin/vim.tiny

RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

RUN a2enmod rewrite

EXPOSE 80
