FROM ossrs/srs:6

# Add 'srs/' to the path so Docker finds it from the repo root
COPY srs/conf/srs.conf /usr/local/srs/conf/srs.conf

EXPOSE 1935 1985 8080

CMD ["/usr/local/srs/objs/srs", "-c", "/usr/local/srs/conf/srs.conf"]