# O serviço não tem dependência em tempo de execução: só o Node, que executa o
# TypeScript direto. A imagem leva o código e mais nada. Base fixada por digest.
FROM node:22.23.3-bookworm-slim@sha256:3ed98443660ff48413b5af19ecefce3b9d50845a901a43420d47cc63a9fddbe9
ENV NODE_ENV=production
WORKDIR /app
COPY --chown=root:root package.json ./
COPY --chown=root:root src src
USER node
EXPOSE 8070
CMD ["node", "src/main.ts"]
