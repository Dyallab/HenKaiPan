FROM golang:1.26-alpine AS build
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest

FROM alpine:3.22
COPY --from=build /go/bin/gosec /usr/local/bin/gosec
ENTRYPOINT ["gosec"]
