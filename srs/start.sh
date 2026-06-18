#!/bin/bash

# Create necessary directories
mkdir -p /var/run/nginx
mkdir -p /var/log/nginx
mkdir -p /etc/nginx/ssl

# Start NGINX in the background
/usr/sbin/nginx -g 'daemon off;' &

# Wait a moment for NGINX to start
sleep 2

# Check if NGINX is running
if ! pgrep -x nginx > /dev/null; then
    echo "ERROR: NGINX failed to start!"
    exit 1
fi

echo "NGINX started successfully on port 1935"

# Start SRS in the foreground (Railway requires the main process to stay in foreground)
exec /usr/local/srs/objs/srs -c /usr/local/srs/conf/srs.conf