# Week 4 - Advanced Threat Detection & Web Security

## Project Overview

This project implements advanced web security techniques using Node.js and Express.js.

## Features Implemented

- Rate Limiting using express-rate-limit
- API Key Authentication
- CORS Configuration
- Helmet Security Headers
- Content Security Policy (CSP)
- HSTS Security
- Failed Login Monitoring
- Protected API Routes

## Technologies Used

- Node.js
- Express.js
- Helmet
- CORS
- express-rate-limit
- dotenv
- Postman

## API Endpoints

### Login Route

POST /login

### Private API

GET /api/private

### Dashboard Route

GET /dashboard

## Installation

### Install Dependencies

```bash
npm install
```

### Run Server

```bash
node server.js
```

## Environment Variables

Create `.env` file:

```env
PORT=5000
JWT_SECRET=mysecret123
API_KEY=myapikey123
```

## Security Features

### Rate Limiting

Protects APIs from brute-force attacks.

### API Authentication

Secures endpoints using API keys.

### CSP

Prevents script injection attacks.

### HSTS

Enforces HTTPS communication.

### Failed Login Monitoring

Detects repeated failed login attempts.

## Testing

APIs tested using Postman.
