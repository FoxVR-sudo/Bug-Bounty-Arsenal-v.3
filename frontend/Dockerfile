# React frontend Dockerfile - Production Build
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy application code
COPY . .

# Accept build args (passed from docker-compose)
ARG REACT_APP_API_URL
ENV REACT_APP_API_URL=$REACT_APP_API_URL

ARG REACT_APP_TURNSTILE_ENABLED
ENV REACT_APP_TURNSTILE_ENABLED=$REACT_APP_TURNSTILE_ENABLED

ARG REACT_APP_TURNSTILE_SITE_KEY
ENV REACT_APP_TURNSTILE_SITE_KEY=$REACT_APP_TURNSTILE_SITE_KEY

ARG REACT_APP_ENABLE_WS=true
ENV REACT_APP_ENABLE_WS=$REACT_APP_ENABLE_WS

# Build for production
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app

# Install serve-handler locally
RUN npm install serve-handler

# Copy built files
COPY --from=builder /app/build ./build

# Copy server script
COPY server.js ./

# Expose port
EXPOSE 3000

# Start production server
CMD ["node", "server.js"]
