#!/bin/bash

# 1. Clean up stale PID files (Crucial for Docker restarts)
rm -f /run/nginx.pid
rm -f /var/run/nginx.pid

# 2. Ensure log directories exist
mkdir -p /var/log/nginx
mkdir -p /var/run

# 3. Start NGINX
/usr/sbin/nginx

# 4. Start SRS in the foreground
exec /usr/local/srs/objs/srs -c /usr/local/srs/conf/srs.conf