FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/ntwire-server ./cmd/ntwire-server
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ntwire-server /ntwire-server
USER nonroot:nonroot
ENTRYPOINT ["/ntwire-server"]
