# Use Playwright official image which already contains browsers + deps
FROM mcr.microsoft.com/playwright:latest

# set workdir
WORKDIR /usr/src/app

# copy package manifests first (for caching)
COPY package.json package-lock.json* ./

# install npm deps (production)
RUN npm ci --production

# copy app source
COPY . .

# create writable dirs for uploads/logs
RUN mkdir -p uploads logs public && chown -R pwuser:pwuser /usr/src/app/uploads /usr/src/app/logs /usr/src/app/public

# switch to non-root user that Playwright image uses
USER pwuser

# expose port (match your app)
EXPOSE 3000

# env defaults (override at runtime)
ENV NODE_ENV=production
ENV PORT=3000
ENV ADMIN_TOKEN=please_set_a_secret_token
# Optionally enable cookie validation
ENV VALIDATE_COOKIES=true

# start server
CMD ["node", "server.js"]
