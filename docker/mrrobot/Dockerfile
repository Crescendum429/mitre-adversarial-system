FROM php:8.1-apache

RUN apt-get update && apt-get install -y \
    nmap \
    john \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash robot

COPY www/ /var/www/html/

RUN set -eux; \
    pass=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12); \
    sed -i "s/__PASSWORD_PLACEHOLDER__/${pass}/g" /var/www/html/wp-login.php; \
    echo "$pass" >> /var/www/html/fsocity.dic; \
    robot_pass=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 10); \
    robot_md5=$(echo -n "$robot_pass" | md5sum | cut -d' ' -f1); \
    echo "robot:$robot_md5" > /home/robot/password.raw-md5; \
    echo "$robot_pass" >> /var/www/html/fsocity.dic; \
    echo "robot:$robot_pass" | chpasswd

RUN echo "822c73956184f694993bede3eb39f959" > /home/robot/key-2-of-3.txt && \
    chown robot:robot /home/robot/key-2-of-3.txt /home/robot/password.raw-md5 && \
    chmod 0644 /home/robot/password.raw-md5 && \
    chmod 0600 /home/robot/key-2-of-3.txt && \
    chmod 755 /home/robot

RUN echo "04787ddef27c3dee1ee161b21670b4e4" > /root/key-3-of-3.txt && \
    chmod 600 /root/key-3-of-3.txt

RUN chmod u+s /usr/bin/python3

RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

RUN a2enmod rewrite

EXPOSE 80
