FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /muffin-currency

FROM alpine:latest

COPY --from=builder /muffin-currency /muffin-currency
EXPOSE 8080

CMD ["/muffin-currency"]
