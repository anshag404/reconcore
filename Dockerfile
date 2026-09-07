# Stage 1: Build the React Frontend
FROM node:18-alpine AS frontend-builder
WORKDIR /app/frontend

# Copy frontend dependencies and build
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Setup the Express Backend with Nmap
FROM node:18-alpine
WORKDIR /app

# Install Nmap and required scripts
RUN apk update && apk add --no-cache nmap nmap-scripts

# Copy backend dependencies
COPY package*.json ./
RUN npm install --production

# Copy backend source code
COPY src/ ./src/

# Copy built frontend assets from Stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Expose the API and Frontend Port
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
