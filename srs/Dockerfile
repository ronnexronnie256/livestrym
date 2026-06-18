FROM ossrs/srs:6

# Install NGINX inside the SRS container
RUN apt-get update && apt-get install -y nginx && rm -rf /var/lib/apt/lists/*

# Copy SRS config
COPY srs/conf/srs.conf /usr/local/srs/conf/srs.conf

# Copy NGINX config (include srs/ prefix)
COPY srs/nginx.conf /etc/nginx/nginx.conf

# Copy TLS certificates
COPY srs/conf/server.crt /etc/nginx/ssl/server.crt
COPY srs/conf/server.key /etc/nginx/ssl/server.key

# Secure the private key
RUN chmod 600 /etc/nginx/ssl/server.key

# Copy the startup script (include srs/ prefix)
COPY srs/start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 1935 1985 8080

# Run the script that starts both NGINX and SRS
CMD ["/start.sh"]