FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway && CGO_ENABLED=0 go build -o /out/seed ./cmd/seed

FROM alpine:3.22
RUN adduser -D appuser
WORKDIR /app
COPY --from=build /out/ ./
USER appuser
EXPOSE 8080
CMD ["/app/gateway"]
