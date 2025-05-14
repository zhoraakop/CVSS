const express = require('express');
const cors = require('cors');
const connectDB = require('./db');
const evaluateRouter = require('./routes/evaluate');
const scanRouter = require('./routes/scan');

const app = express();
const PORT = 5000;

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Routes
app.use('/api/scan', scanRouter);
app.use('/api/evaluate', evaluateRouter);

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false,
    error: 'Internal server error' 
  });
});

// Start server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});