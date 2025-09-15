FROM node:20-bullseye

# System deps (chromium + playwright need)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    fonts-liberation \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libpango-1.0-0 \
    libxcursor1 \
    libxss1 \
    wget \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --omit=dev

# Install browsers (headless chromium etc.)
RUN npx playwright install --with-deps

COPY . .

ENV NODE_ENV=production
ENV VALIDATE_COOKIES=true

EXPOSE 3000
CMD ["node", "server.js"]
