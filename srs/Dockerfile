FROM ossrs/srs:6

# Install NGINX inside the SRS container
RUN apt-get update && apt-get install -y nginx && rm -rf /var/lib/apt/lists/*

# Copy SRS config
COPY conf/srs.conf /usr/local/srs/conf/srs.conf

# Copy NGINX config (overwrites the default)
COPY nginx.conf /etc/nginx/nginx.conf

# Copy TLS certificates
COPY conf/server.crt /etc/nginx/ssl/server.crt
COPY conf/server.key /etc/nginx/ssl/server.key

# Secure the private key
RUN chmod 600 /etc/nginx/ssl/server.key

# Copy the startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 1935 1985 8080

# Run the script that starts both NGINX and SRS
CMD ["/start.sh"]