FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY index.html vite.config.ts tsconfig*.json postcss.config.js eslint.config.js components.json robots.txt ./
COPY public ./public
COPY src ./src

EXPOSE 3000

CMD ["npm", "run", "dev"]
