FROM alpine:3.20
RUN apk add --no-cache bash git grep && git config --system safe.directory '*'
COPY ghostaction-scan.sh test.sh /
ENTRYPOINT ["/ghostaction-scan.sh"]
CMD ["/scan"]
