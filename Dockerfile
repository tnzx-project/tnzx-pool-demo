FROM node:20-alpine

LABEL org.opencontainers.image.title="TNZX VS3 Protocol Demo"
LABEL org.opencontainers.image.description="Reference implementation of VS3 steganographic messaging over Monero mining"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY package.json .
COPY src/ src/
COPY vs3-client.js .
COPY test-ghost.js .
COPY examples/ examples/

# No npm install needed — zero external dependencies (only Node.js built-ins)

EXPOSE 4444
EXPOSE 8090

ENV STRATUM_PORT=4444 \
    API_PORT=8090 \
    DAEMON_HOST=127.0.0.1 \
    DAEMON_PORT=18081 \
    GHOST_DIFF_MAX=500

CMD ["node", "src/stratum-demo.js"]
