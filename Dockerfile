FROM --platform=$BUILDPLATFORM golang:1.19-alpine as builder

ARG RELEASE_VERSION=development

# Install our build tools
RUN apk add --update ca-certificates

WORKDIR /go/src/github.com/daspawnw/trivy-java-db-server

ARG TARGETOS
ARG TARGETARCH
ENV LDFLAGS "-X 'main.VERSION=${RELEASE_VERSION}' "

COPY . ./

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="$LDFLAGS" -o bin/trivy-java-db-server ./cmd/server

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/github.com/daspawnw/trivy-java-db-server/bin/trivy-java-db-server /trivy-java-db-server

ENTRYPOINT ["/trivy-java-db-server"]