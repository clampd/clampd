FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ── Runtime ────────────────────────────────────────────────────────────
FROM node:22-alpine

RUN addgroup -g 1001 clampd && adduser -D -u 1001 -G clampd clampd

WORKDIR /app

COPY --from=builder /app/package.json /app/package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts

COPY --from=builder /app/dist/ ./dist/

# Copy fleet config if present (for fleet mode)
COPY fleet*.json ./

USER clampd
EXPOSE 3003

# Single mode: reads config from env vars
# Fleet mode: set CMD to ["node", "dist/index.js", "--fleet-config", "fleet.json"]
CMD ["node", "dist/index.js"]
