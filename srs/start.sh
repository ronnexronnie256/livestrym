#!/bin/bash

# Start NGINX. 
# By NOT using 'daemon off;', NGINX will automatically detach and run safely in the background.
/usr/sbin/nginx

# Start SRS in the foreground. 
# The 'exec' command makes SRS the main process (PID 1) so Railway can monitor it.
exec /usr/local/srs/objs/srs -c /usr/local/srs/conf/srs.conf