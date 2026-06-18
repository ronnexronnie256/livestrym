FROM nginx:alpine

# Remove default NGINX config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom stream configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy TLS certificates into the container
COPY server.crt /etc/nginx/ssl/server.crt
COPY server.key /etc/nginx/ssl/server.key

# Secure the private key
RUN chmod 600 /etc/nginx/ssl/server.key

# Expose the RTMPS port
EXPOSE 1935

# Start NGINX in the foreground
CMD ["nginx", "-g", "daemon off;"]