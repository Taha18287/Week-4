require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());

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
    INTRUSION DETECTION (NEW)
========================= */

let failedAttempts = {};

const MAX_FAILED_ATTEMPTS = 5;

function logAlert(ip, count) {

  console.log(` ALERT: Suspicious activity detected`);
  console.log(`IP: ${ip}`);
  console.log(`Failed Attempts: ${count}`);
}

/* =========================
   ROUTES
========================= */

app.get('/', (req, res) => {

  res.send('Secure Server Running');

});

/* =========================
   API KEY PROTECTED ROUTE
========================= */

app.get(
  '/api/private',
  apiKeyMiddleware,
  (req, res) => {

    res.json({
      success: true,
      message: 'Private API Access Granted'
    });

  }
);

/* =========================
   LOGIN (WITH IDS ADDED)
========================= */

app.post('/login', (req, res) => {

  const ip = req.ip;
  const { username, password } = req.body;

  const validUser = 'admin';
  const validPass = '12345';

  //  FAILED LOGIN
  if (username !== validUser || password !== validPass) {

    // count failed attempts
    failedAttempts[ip] = (failedAttempts[ip] || 0) + 1;

    console.log(` Failed login from ${ip}: ${failedAttempts[ip]}`);

    // ALERT TRIGGER
    if (failedAttempts[ip] >= MAX_FAILED_ATTEMPTS) {

      logAlert(ip, failedAttempts[ip]);

    }

    return res.status(401).json({
      message: 'Invalid credentials'
    });
  }

  // ✅ SUCCESS LOGIN → reset counter
  failedAttempts[ip] = 0;

  const token = jwt.sign(
    { username: validUser },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ token });

});

/* =========================
   DASHBOARD (JWT PROTECTED)
========================= */

app.get(
  '/dashboard',
  verifyToken,
  (req, res) => {

    res.json({
      message: 'Protected Dashboard',
      user: req.user
    });

  }
);

/* =========================
   START SERVER
========================= */

app.listen(process.env.PORT, () => {

  console.log(`Server running on port ${process.env.PORT}`);

});
