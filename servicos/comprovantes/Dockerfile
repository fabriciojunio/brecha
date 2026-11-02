# Binário estático numa base sem shell nem gerenciador de pacotes. Bases
# fixadas por digest.
FROM golang:1.26.9@sha256:37cfcca63222ec499bec5e8ad7aad52dbf7529db36d5812b8eae2f0621aa92d6 AS construcao
WORKDIR /src
COPY go.mod ./
COPY comprovante.go main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /comprovantes .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=construcao /comprovantes /comprovantes
USER nonroot
EXPOSE 8090
ENTRYPOINT ["/comprovantes"]
