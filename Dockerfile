FROM docker.io/library/golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /runtime-attestor .

FROM docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
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
