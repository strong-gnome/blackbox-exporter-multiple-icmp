FROM golang:alpine as builder

ADD     ./   /etc/bb-pre-build/
WORKDIR /etc/bb-pre-build
RUN go build -o /etc/bb-pre-build/blackbox-exporter

FROM alpine:latest
COPY --from=builder /etc/bb-pre-build/blackbox-exporter /bin/blackbox-exporter
COPY --from=builder /etc/bb-pre-build/blackbox.yml      /etc/blackbox_exporter/config.yml

EXPOSE 9115
ENTRYPOINT [ "/bin/blackbox-exporter" ]
CMD        [ "--config.file=/etc/blackbox_exporter/config.yml" ]
