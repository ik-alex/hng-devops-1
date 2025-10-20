# use the official nodejs image as a base
FROM node:latest

# setup the working directory
WORKDIR /app

# copy the application files
COPY . .

# install dependencies
RUN npm install

# Expose the port the development server runs on
EXPOSE 5173

# start the server
CMD ["npm", "run", "dev"]