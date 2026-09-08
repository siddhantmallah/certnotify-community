# certnotify — open-source internet exposure scanner
#
# Build:  docker build -t certnotify .
# Run:    docker run --rm certnotify scan example.com
#
# Stateful checks keep their baseline in ~/.certnotify/state, which is gone
# when the container exits. Mount a volume to make them useful across runs:
#   docker run --rm -v certnotify-state:/home/certnotify/.certnotify \
#     certnotify dns-monitor example.com

# ── build ───────────────────────────────────────────────────────────────────
FROM node:22-alpine AS build

WORKDIR /app

# Dependencies first, so a source-only change does not re-resolve the tree.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsup.config.ts ./
COPY src ./src
RUN npm run build

# ── runtime ─────────────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime

ENV NODE_ENV=production
WORKDIR /app

# Only the two runtime dependencies (commander, picocolors) — the build
# toolchain and the test suite do not ship in the image.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build /app/dist ./dist

# A scanner has no reason to run as root. The state directory is created and
# owned up front so the stateful checks can write to a mounted volume without
# needing a writable /app or a root-owned home.
RUN addgroup -S certnotify \
 && adduser -S -G certnotify -h /home/certnotify certnotify \
 && mkdir -p /home/certnotify/.certnotify/state \
 && chown -R certnotify:certnotify /home/certnotify

USER certnotify
VOLUME ["/home/certnotify/.certnotify"]

ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]

LABEL org.opencontainers.image.title="certnotify" \
      org.opencontainers.image.description="Open-source internet exposure scanner — SSL/TLS, DNS, DNSSEC, email security, HTTP headers, open ports, DNSBL reputation, uptime, and stateful monitoring checks." \
      org.opencontainers.image.source="https://github.com/siddhantmallah/certnotify-community" \
      org.opencontainers.image.url="https://www.certnotify.com" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
