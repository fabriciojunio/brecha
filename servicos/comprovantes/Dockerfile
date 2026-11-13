# Binário estático numa base sem shell nem gerenciador de pacotes. Bases
# fixadas por digest.
FROM golang:1.26.11@sha256:957952ae74dc010608717144399a59a2c6e82ea03d63be1c7ff6577c5a135f93 AS construcao
WORKDIR /src
COPY go.mod ./
COPY comprovante.go main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /comprovantes .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=construcao /comprovantes /comprovantes
USER nonroot
EXPOSE 8090
ENTRYPOINT ["/comprovantes"]
