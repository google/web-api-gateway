FROM golang

ADD . /go/src/web-api-gateway

RUN go get web-api-gateway/server
RUN go install web-api-gateway/server
RUN go install web-api-gateway/setuptool

ENTRYPOINT /go/bin/server

EXPOSE 443
