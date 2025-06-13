const express = require('express');
const router = express.Router();
const { cvss_score, macroVector } = require('../CVSSScore');
const cvssLookup_global = require('../CVSSLookup');
const { maxSeverity } = require('../MaxSeverity');

// Все метрики CVSS 4.0
const CVSS4_METRICS = {
  // Base Metrics (обязательные)
  AV: ['N', 'A', 'L', 'P'],  // Вектор атаки
  AC: ['L', 'H'], // Сложность атаки
  AT: ['N', 'P'], // Требования к атаке
  PR: ['N', 'L', 'H'], // Уровень привилегий
  UI: ['N', 'P', 'A'], // Взаимодействие с пользователем
  VC: ['H', 'L', 'N'], // Влияние на конфиденциальност
  VI: ['H', 'L', 'N'], // Влияние на целостность
  VA: ['H', 'L', 'N'], // Влияние на доступность
  SC: ['H', 'L', 'N'], // Влияние на конфиденциальность
  SI: ['H', 'L', 'N'], // Влияние на целостность
  SA: ['H', 'L', 'N'], // Влияние на доступность
  // Threat Metrics
  E: ['X', 'A', 'P', 'U'],
  // Environmental Metrics
  CR: ['X', 'H', 'M', 'L'],
  IR: ['X', 'H', 'M', 'L'],
  AR: ['X', 'H', 'M', 'L'],
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MAT: ['X', 'N', 'P'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'P', 'A'],
  MVC: ['X', 'H', 'L', 'N'],
  MVI: ['X', 'H', 'L', 'N'],
  MVA: ['X', 'H', 'L', 'N'],
  MSC: ['X', 'H', 'L', 'N'],
  MSI: ['X', 'S', 'H', 'L', 'N'],
  MSA: ['X', 'S', 'H', 'L', 'N'], 
  // Supplemental Metrics
  S: ['X', 'N', 'P'],
  AU: ['X', 'N', 'Y'],
  R: ['X', 'A', 'U', 'I'],
  V: ['X', 'D', 'C'],
  RE: ['X', 'L', 'M', 'H'],
  U: ['X', 'Clear', 'Green', 'Amber', 'Red']
};

function validateVector(vector) {
  if (!vector.startsWith('CVSS:4.0/')) {
    return { valid: false, error: 'Префикс CVSS:4.0/ обязателен' };
  }

  const parts = vector.split('/').slice(1);
  const metrics = {};
  const mandatory = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

  for (const part of parts) {
    const [metric, value] = part.split(':');
    
    if (!CVSS4_METRICS[metric]) {
      return { valid: false, error: `Неизвестная метрика: ${metric}` };
    }
    
    if (!CVSS4_METRICS[metric].includes(value)) {
      return { valid: false, error: `Недопустимое значение для ${metric}: ${value}` };
    }
    
    metrics[metric] = value;
  }

  const missing = mandatory.filter(m => !metrics[m]);
  if (missing.length > 0) {
    return { valid: false, error: `Отсутствуют обязательные метрики: ${missing.join(', ')}` };
  }

  return { valid: true, metrics };
}

router.post('/', (req, res) => {
  try {
    const { vector } = req.body;
    console.log('Получен вектор:', vector);

    const validation = validateVector(vector);
    if (!validation.valid) {
      return res.status(400).json({
        success: false,
        error: validation.error,
        receivedVector: vector,
        example: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
      });
    }

    // Добавляем дефолтные значения для отсутствующих метрик
    const allMetrics = {
      E: 'X', CR: 'X', IR: 'X', AR: 'X',
      MAV: 'X', MAC: 'X', MAT: 'X', MPR: 'X', MUI: 'X',
      MVC: 'X', MVI: 'X', MVA: 'X', MSC: 'X', MSI: 'X', MSA: 'X',
      S: 'X', AU: 'X', R: 'X', V: 'X', RE: 'X', U: 'X',
      ...validation.metrics
    };

    const macroVec = macroVector(allMetrics);
    const score = cvss_score(allMetrics, cvssLookup_global, maxSeverity, macroVec);
    const severity = score === 0 ? 'Отсутствует' :
                    score < 4 ? 'Низкая' :
                    score < 7 ? 'Средняя' :
                    score < 9 ? 'Высокая' : 'Критическая';

    res.json({
      success: true,
      vector,
      score: parseFloat(score.toFixed(1)),
      severity,
      macroVector: macroVec
    });

  } catch (err) {
    console.error('Ошибка расчета:', err);
    res.status(500).json({
      success: false,
      error: 'Внутренняя ошибка сервера'
    });
  }
});

module.exports = router;