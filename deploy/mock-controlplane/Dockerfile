FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/mock-controlplane ./main.go

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build /out/mock-controlplane /mock-controlplane
COPY ui /ui
ENV UI_DIR=/ui
EXPOSE 8081
ENTRYPOINT ["/mock-controlplane"]
