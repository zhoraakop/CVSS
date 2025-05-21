const mongoose = require('mongoose');

const vulnerabilitySchema = new mongoose.Schema({
  zapPluginId: {
    type: String,
    required: true,
    index: true
  },
  name: {
    type: String,
    required: true,
    index: true
  },
  description: String,
  cvssScore: {
    type: Number,
    min: 0,
    max: 10,
    default: 0
  },
  cvssVector: {                      // ← Новое поле
    type: String,
    default: ''
  },
  riskLevel: {
    type: String,
    enum: ['Информационный', 'Низкий', 'Средний', 'Высокий', 'Критический'],
    required: true
  },
  recommendation: {
    type: String,
    required: true
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  }
}, {
  autoIndex: true
});

// Составной индекс для быстрого поиска
vulnerabilitySchema.index({
  zapPluginId: 1,
  name: 1,
  riskLevel: 1
});

module.exports = mongoose.model('Vulnerability', vulnerabilitySchema);
