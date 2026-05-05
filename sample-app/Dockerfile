FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
COPY main.go ./
RUN go mod download
RUN CGO_ENABLED=0 go build -o /out/sample-app ./main.go

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build /out/sample-app /sample-app
EXPOSE 8080
ENTRYPOINT ["/sample-app"]
