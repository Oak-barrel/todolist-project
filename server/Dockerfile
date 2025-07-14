FROM node:18

WORKDIR /app

COPY server/package*.json ./
RUN npm install

COPY server/ .

COPY proto ./proto

CMD ["node", "server.js"]