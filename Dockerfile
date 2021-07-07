FROM golang

ENV GO111MODULE=on

ADD . /go/src/github.com/google/web-api-gateway

RUN go get github.com/google/web-api-gateway/server@latest
RUN go install github.com/google/web-api-gateway/server@latest
RUN go install github.com/google/web-api-gateway/setuptool@latest
RUN go install github.com/google/web-api-gateway/connectiontest@latest

ENTRYPOINT ["/go/bin/server"]

EXPOSE 443
