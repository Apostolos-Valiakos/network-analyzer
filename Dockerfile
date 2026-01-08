# --- Stage 1: Build the Application ---
FROM node:lts-alpine AS build-stage

WORKDIR /app

# 1. Copy package.json and package-lock.json (if available)
# Doing this before copying the rest of the code caches the install step
COPY package*.json ./

# 2. Install dependencies
RUN npm install

# 3. Copy the rest of the application source code
COPY . .

# 4. Build the app
# Generates the static 'dist' folder required for Nginx
RUN npm run generate

# --- Stage 2: Serve with Nginx ---
FROM nginx:stable-alpine AS production-stage

# Nuxt static generation outputs to '/dist' inside the '/app' directory
COPY --from=build-stage /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]