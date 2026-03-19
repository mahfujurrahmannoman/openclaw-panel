FROM node:22-alpine

# Install build tools for native modules (better-sqlite3, node-pty) + Docker CLI
RUN apk add --no-cache python3 make g++ git docker-cli util-linux linux-headers

WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm install --production --ignore-scripts=false

# Copy application code
COPY src/ ./src/
COPY public/ ./public/

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 3001 2222

CMD ["node", "src/server.js"]
