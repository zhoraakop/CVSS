const express = require('express');
const cors = require('cors');
const connectDB = require('./utils/DB');
const evaluateRouter = require('./routes/Evaluate');
const scanRouter = require('./routes/Scan');
const vulnerabilityRouter = require('./routes/Vulnerability');

const app = express();
const PORT = 5000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use('/api/scan', scanRouter);
app.use('/api/evaluate', evaluateRouter);
app.use('/api/vulnerabilities', vulnerabilityRouter);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false,
    error: 'Internal server error' 
  });
});

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});