FROM docker.io/library/golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /runtime-attestor .

FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN mkdir -p /var/lib/secure-ai/logs /var/lib/secure-ai/reports && \
    chown -R 65534:65534 /var/lib/secure-ai
COPY --from=build /runtime-attestor /usr/local/bin/runtime-attestor
COPY policies/default-policy.yaml /etc/secure-ai/policy/attestor.yaml
USER 65534:65534
EXPOSE 8485
VOLUME ["/var/lib/secure-ai"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD wget -q -T 3 -O - http://127.0.0.1:8485/health >/dev/null || exit 1
ENTRYPOINT ["runtime-attestor"]
CMD ["daemon"]
