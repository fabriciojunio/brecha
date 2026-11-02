# Imagem do laboratório, como ela costuma chegar a produção: JRE completa, com
# shell e curl "para o healthcheck". É o que a pós-exploração do relatório usa
# depois do BRECHA-017. A versão endurecida está em Dockerfile.corrigido.
FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS construcao
WORKDIR /construcao
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src src
RUN mvn -B -q -DskipTests package && cp target/brecha-*.jar aplicacao.jar

FROM eclipse-temurin:21.0.12_8-jre-noble@sha256:7739f0ffce786528961eea6bf46d9610ee968ac6127c9b2e93494757bdecce9f
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=construcao /construcao/aplicacao.jar aplicacao.jar
EXPOSE 8080
# Qualquer resposta HTTP, até 401, prova que a aplicação está de pé.
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD curl -s -o /dev/null http://127.0.0.1:8080/v2/contas/100
ENTRYPOINT ["java", "-jar", "/app/aplicacao.jar", "--server.address=0.0.0.0"]
