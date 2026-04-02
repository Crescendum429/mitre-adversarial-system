FROM php:8.1-apache

RUN apt-get update && apt-get install -y \
    nmap \
    john \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash robot && \
    echo "robot:abcdefghijklmnopqrstuvwxyz" | chpasswd

COPY www/ /var/www/html/

RUN echo "822c73956184f694993bede3eb39f959" > /home/robot/key-2-of-3.txt && \
    echo "robot:c3fcd3d76192e4007dfb496cca67e13b" > /home/robot/password.raw-md5 && \
    chown robot:robot /home/robot/key-2-of-3.txt /home/robot/password.raw-md5 && \
    chmod 644 /home/robot/key-2-of-3.txt /home/robot/password.raw-md5 && \
    chmod 755 /home/robot

RUN echo "04787ddef27c3dee1ee161b21670b4e4" > /root/key-3-of-3.txt && \
    chmod 600 /root/key-3-of-3.txt

RUN chmod u+s /usr/bin/python3

RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

RUN a2enmod rewrite

EXPOSE 80
