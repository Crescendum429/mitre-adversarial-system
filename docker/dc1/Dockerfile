FROM php:8.1-apache

RUN apt-get update && apt-get install -y \
    nmap \
    john \
    python3 \
    findutils \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash flag4

COPY www/ /var/www/html/

RUN set -eux; \
    pass=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12); \
    sed -i "s/__USERNAME__/admin/g" /var/www/html/wp-login.php /var/www/html/wp-admin/theme-editor.php; \
    sed -i "s/__PASSWORD_PLACEHOLDER__/${pass}/g" /var/www/html/wp-login.php; \
    echo "$pass" >> /var/www/html/fsocity.dic; \
    flag4_pass=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 10); \
    flag4_md5=$(echo -n "$flag4_pass" | md5sum | cut -d' ' -f1); \
    echo "flag4:$flag4_md5" > /home/flag4/password.raw-md5; \
    echo "$flag4_pass" >> /var/www/html/fsocity.dic; \
    echo "flag4:$flag4_pass" | chpasswd

RUN echo "b7493bcd4a32ff4ca1fb4b9db8d08fc5" > /var/www/html/flag1.txt && \
    echo "orlfyezaj1d1lrl1hf2b6e1hq8f3w2r5" > /home/flag4/flag4-of-5.txt && \
    chown flag4:flag4 /home/flag4/flag4-of-5.txt /home/flag4/password.raw-md5 && \
    chmod 0644 /home/flag4/password.raw-md5 /var/www/html/flag1.txt && \
    chmod 0600 /home/flag4/flag4-of-5.txt && \
    chmod 755 /home/flag4

RUN echo "a8f0d4e7c213e81f9b2a5c6d7e8f901b" > /root/thefinalflag.txt && \
    chmod 600 /root/thefinalflag.txt

# SUID find: permite priv esc via `find /bin/mv -exec /bin/sh -p ;`
# Reemplaza SUID python3 que usaba mrrobot.
RUN chmod u+s /usr/bin/find

RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

RUN a2enmod rewrite

EXPOSE 80
