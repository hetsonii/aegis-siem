FROM node:20-alpine
WORKDIR /app
# The app uses only Node built-in modules (http, fs, url) plus global fetch,
# so there are no dependencies to install - the build never touches a registry.
COPY server.js products.js ./
COPY public ./public
ENV PORT=8080
EXPOSE 8080
USER node
CMD ["node", "server.js"]
