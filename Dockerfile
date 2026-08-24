# Build and run the MCP server over stdio. Used by Glama's automated check
# (the server only needs to start and answer an introspection request).
FROM node:20-slim
WORKDIR /app
COPY . .
RUN npm install && npm run build
ENV NODE_ENV=production
ENTRYPOINT ["node", "dist/index.js"]
