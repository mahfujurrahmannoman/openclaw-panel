FROM node:22-alpine

# Install build tools for better-sqlite3 native module + Docker CLI for exec
RUN apk add --no-cache python3 make g++ git docker-cli

WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci --production

# Copy application code
COPY src/ ./src/
COPY public/ ./public/

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 3001

CMD ["node", "src/server.js"]
