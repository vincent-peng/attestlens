FROM node:20.12.2-alpine

WORKDIR /app
COPY --chown=node:node server.js ./server.js

USER node
HEALTHCHECK CMD node -e "process.exit(0)"

CMD ["node", "server.js"]
