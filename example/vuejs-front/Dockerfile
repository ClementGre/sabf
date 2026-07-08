# Use a multi-stage build to create a small, optimized production image.

# 1. Build stage: Install dependencies and build the frontend application.
FROM node:24-alpine AS build
WORKDIR /app

# Copy package.json and pnpm-lock.yaml and install dependencies
COPY ./package.json ./package-lock.json ./
RUN npm i

# Copy the rest of the application source code
COPY . .

# Build the application
RUN npm run build

# 2. Production stage: Serve the built application with a lightweight web server.
FROM nginx:1.25-alpine AS prod
WORKDIR /usr/share/nginx/html

# Copy the built application from the build stage
COPY --from=build /app/dist .

# SPA fallback: redirect unknown paths (e.g. /settings) to index.html
COPY ./nginx.conf /etc/nginx/conf.d/default.conf

# Entrypoint regenerates env.js from container env vars at startup, so
# VITE_API_BASE_URL can be overridden without rebuilding.
COPY ./docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose port 80
EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
