require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const app = express();

/* =========================
   BODY PARSERS (FIXED ISSUE)
========================= */

// IMPORTANT: this fixes req.body = undefined
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =========================
   SECURITY HEADERS
========================= */

app.use(helmet());

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"]
    }
  })
);

app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  })
);

/* =========================
   CORS
========================= */

app.use(cors({
  origin: ['http://localhost:3000']
}));

/* =========================
   RATE LIMITING
========================= */

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many requests'
});

app.use('/api', limiter);

/* =========================
   API KEY MIDDLEWARE
========================= */

const apiKeyMiddleware = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];

  if (apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      message: 'Invalid API Key'
    });
  }

  next();
};

/* =========================
   JWT MIDDLEWARE
========================= */

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      message: 'No token'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({
      message: 'Invalid token'
    });
  }
};

/* =========================
   IDS (FAILED LOGIN TRACKING)
========================= */

let failedAttempts = {};
const MAX_FAILED_ATTEMPTS = 5;

/* =========================
   ROUTES
========================= */

app.get('/', (req, res) => {
  res.send('Secure Server Running');
});

/* =========================
   API ROUTE
========================= */

app.get('/api/private', apiKeyMiddleware, (req, res) => {
  res.json({
    success: true,
    message: 'Private API Access Granted'
  });
});

/* =========================
   LOGIN (FIXED SAFE VERSION)
========================= */

app.post('/login', (req, res) => {

  const ip = req.ip;

  // ✅ FIX: safe extraction prevents crash
  const username = req.body?.username || "";
  const password = req.body?.password || "";

  const validUser = 'admin';
  const validPass = '12345';

  if (username !== validUser || password !== validPass) {

    failedAttempts[ip] = (failedAttempts[ip] || 0) + 1;

    console.log(`Failed login attempt from ${ip}`);
    console.log(`Attempts: ${failedAttempts[ip]}`);

    if (failedAttempts[ip] >= MAX_FAILED_ATTEMPTS) {
      console.log('ALERT: Suspicious activity detected');
      console.log(`IP Address: ${ip}`);
    }

    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  // reset counter
  failedAttempts[ip] = 0;

  const token = jwt.sign(
    { username: validUser },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({
    success: true,
    message: 'Login successful',
    token
  });
});

/* =========================
   DASHBOARD
========================= */

app.get('/dashboard', verifyToken, (req, res) => {
  res.json({
    message: 'Protected Dashboard',
    user: req.user
  });
});

/* =========================
   START SERVER
========================= */

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
