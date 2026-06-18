#!/bin/bash

# Start NGINX in the background
nginx -g 'daemon off;' &

# Start SRS in the foreground (Railway requires the main process to stay in foreground)
exec /usr/local/srs/objs/srs -c /usr/local/srs/conf/srs.conf