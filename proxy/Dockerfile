FROM node:22-alpine

LABEL maintainer="TNZX Project" \
      description="VS3 Proxy — Universal Stratum steganographic relay" \
      license="LGPL-2.1"

WORKDIR /app

# Copy only what's needed (no dev dependencies, no tests)
COPY proxy/package.json proxy/index.js ./proxy/
COPY proxy/bin/ ./proxy/bin/
COPY poc/vs3-proxy.js ./poc/

# No npm install needed — zero external dependencies

# Default ports: 13333 (Stratum), 19090 (WebSocket relay)
EXPOSE 13333 19090

# Non-root user for security
RUN addgroup -S vs3 && adduser -S vs3 -G vs3
USER vs3

ENTRYPOINT ["node", "proxy/bin/vs3-proxy-cli.js"]
# Default: show help. Override with --upstream pool:port
CMD ["--help"]
