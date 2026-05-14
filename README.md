# Week 4 - Advanced Threat Detection & Web Security
## Project Overview
This project implements advanced web security techniques using Node.js and Express.js.

---


---

## Features Implemented

- Rate Limiting using express-rate-limit
- API Key Authentication
- JWT Authentication
- CORS Configuration
- Helmet Security Headers
- Content Security Policy (CSP)
- HSTS Security
- Failed Login Monitoring
- Intrusion Detection System (IP-based tracking)
- Protected API Routes

---

## Technologies Used

- Node.js
- Express.js
- Helmet
- CORS
- express-rate-limit
- JSON Web Token (JWT)
- dotenv
- Postman

---

## API Endpoints

### 1. Login Route
```
POST /login
```

**Body:**
```json
{
  "username": "admin",
  "password": "12345"
}
```

**Response:**
```json
{
  "token": "JWT_TOKEN_HERE"
}
```

---

### 2. Private API (API Key Required)
```
GET /api/private
```

**Headers:**
```
x-api-key: testkey
```

---

### 3. Dashboard Route (JWT Required)
```
GET /dashboard
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN_HERE
```

---

## Installation

### Install Dependencies
```
npm install
```

### Run Server
```
node server.js
```

---

## Environment Variables

Create `.env` file:

```
PORT=5000
SESSION_SECRET=supersecret123
JWT_SECRET=jwtsecret123
API_KEY=testkey
```

---

## Security Features

### Rate Limiting
Protects APIs from brute-force attacks by limiting requests.

### API Authentication
Secures endpoints using API keys.

### JWT Authentication
Ensures only logged-in users can access protected routes.

### Content Security Policy (CSP)
Prevents XSS (script injection attacks).

### HSTS
Forces secure HTTPS communication.

### Failed Login Monitoring
Tracks incorrect login attempts and logs suspicious activity.

### Intrusion Detection System
Monitors IP-based failed login attempts and triggers alerts after multiple failures.

---

## Testing

All APIs were tested using Postman:

- Login endpoint tested with correct and incorrect credentials
- API key validation tested using headers
- JWT-protected route tested with valid and invalid tokens
- Rate limiting tested by sending multiple requests

---

## Security Summary

This project demonstrates a complete backend security system including authentication, authorization, request limiting, and intrusion detection mechanisms to protect APIs from common cyber attacks.



