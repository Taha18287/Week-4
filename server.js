require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());

/* SECURITY HEADERS */

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

/* CORS */

app.use(cors({
  origin: ['http://localhost:3000']
}));

/* RATE LIMIT */

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many requests'
});

app.use('/api', limiter);

/* API KEY */

const apiKeyMiddleware = (req, res, next) => {

  const apiKey = req.headers['x-api-key'];

  if (apiKey !== process.env.API_KEY) {

    return res.status(401).json({
      message: 'Invalid API Key'
    });

  }

  next();
};

/* JWT VERIFY */

const verifyToken = (req, res, next) => {

  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {

    return res.status(401).json({
      message: 'No token'
    });

  }

  try {

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch {

    return res.status(403).json({
      message: 'Invalid token'
    });

  }
};

/* ROUTES */

app.get('/', (req, res) => {

  res.send('Secure Server Running');

});

/* API KEY ROUTE */

app.get(
  '/api/private',
  apiKeyMiddleware,
  (req, res) => {

    res.json({
      success: true,
      message: 'Private API Access Granted'
    });

});

/* LOGIN */

app.post('/login', (req, res) => {

  const user = {
    id: 1,
    username: 'admin'
  };

  const token = jwt.sign(
    user,
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ token });

});

/* JWT ROUTE */

app.get(
  '/dashboard',
  verifyToken,
  (req, res) => {

    res.json({
      message: 'Protected Dashboard',
      user: req.user
    });

});

/* START SERVER */

app.listen(process.env.PORT, () => {

  console.log(
    `Server running on port ${process.env.PORT}`
  );

});