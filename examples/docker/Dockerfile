# ─── Stage 1: build ───────────────────────────────────────────────────────────
FROM node:20-slim AS builder

WORKDIR /app

# Copy workspace manifests first for layer-caching
COPY package.json package-lock.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/server/package.json ./packages/server/
COPY packages/cli/package.json ./packages/cli/

# Install all workspace dependencies
RUN npm ci

# Copy source
COPY tsconfig.base.json ./
COPY packages/core/src ./packages/core/src
COPY packages/core/tsconfig.json ./packages/core/
COPY packages/server/src ./packages/server/src
COPY packages/server/tsconfig.json ./packages/server/
COPY packages/cli/src ./packages/cli/src
COPY packages/cli/tsconfig.json ./packages/cli/

# Build core → server
RUN npm run build --workspace=packages/core
RUN npm run build --workspace=packages/server
RUN npm run build --workspace=packages/cli

# ─── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM node:20-slim AS runtime

# Optional: install Slither (requires Python 3 + pip)
# RUN apt-get update && apt-get install -y python3-pip && pip3 install slither-analyzer

WORKDIR /app

COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/packages/core/package.json ./packages/core/
COPY --from=builder /app/packages/server/package.json ./packages/server/
COPY --from=builder /app/packages/cli/package.json ./packages/cli/

# Install only production dependencies
RUN npm ci --omit=dev

# Copy compiled output
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/server/dist ./packages/server/dist
COPY --from=builder /app/packages/cli/dist ./packages/cli/dist

EXPOSE 4243

# Run the CLI `serve` command so Docker inherits all CLI flags
ENTRYPOINT ["node", "packages/cli/dist/cli.js", "serve"]
CMD ["--host", "0.0.0.0", "--port", "4243"]
