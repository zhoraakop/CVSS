const express = require('express');
const router = express.Router();
const axios = require('axios');
const Vulnerability = require('../models/Schema');

function normalizeRisk(risk) {
  if (!risk) return 'Информационный';

  const map = {
    'высокий': 'Высокий',
    'high': 'Высокий',
    'средний': 'Средний',
    'medium': 'Средний',
    'низкий': 'Низкий',
    'low': 'Низкий',
    'informational': 'Информационный'
  };

  return map[risk.toLowerCase()] || 'Информационный';
}

function calculateStats(results) {
  return {
    total: results.length,
    matched: results.filter(r => r.matched).length,
    high: results.filter(r => r.risk === 'Высокий').length,
    medium: results.filter(r => r.risk === 'Средний').length,
    low: results.filter(r => r.risk === 'Низкий').length,
    info: results.filter(r => r.risk === 'Информационный').length
  };
}

router.post('/', async (req, res) => {
  try {
    const zapReport = req.body;
    const results = [];
    const unmatchedAlerts = new Set();

    for (const site of zapReport.site || []) {
      for (const alert of site.alerts || []) {
        try {
          function escapeRegExp(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          }
          const alertName = (alert.name || alert.alert || '').trim();
          const pluginId = alert.alertRef?.toString() || 'unknown';

          const escapedName = escapeRegExp(alertName.slice(0, 50));

          const vulnerability = await Vulnerability.findOne({
            $or: [
              { zapPluginId: pluginId },
              { name: new RegExp(escapedName, 'i') }
            ]
          });

          const entry = {
            originalName: alertName,
            pluginId,
            solution: alert.solution,
            risk: normalizeRisk(alert.riskdesc?.split(' ')[0]),
            riskcode: alert.riskcode || '',
            reference: alert.reference,
          };

          let cvssScore = null;
          let cvssSeverity = null;

          if (vulnerability?.cvssVector) {
            try {
              const response = await axios.post('http://localhost:5000/api/evaluate', {
                vector: vulnerability.cvssVector
              });

              if (response.data.success) {
                cvssScore = response.data.score;
                cvssSeverity = response.data.severity;
              }
            } catch (error) {
              console.error(`Ошибка при расчете CVSS для ${alertName}:`, error.message);
            }
          }

          results.push({
            ...entry,
            matched: !!vulnerability,
            recommendation: vulnerability?.recommendation || 'Требуется ручной анализ',
            cvssVector: vulnerability?.cvssVector || null,
            cvssScore,
            cvssSeverity
          });
        } catch (err) {
          console.error(`Ошибка обработки alert: ${err.message}`);
        }
      }
    }

    res.json({
      success: true,
      data: results,
      unmatched: [...unmatchedAlerts],
      stats: calculateStats(results)
    });
  } catch (err) {
    console.error("Ошибка сервера:", err);
    res.status(500).json({ success: false, error: "Ошибка сервера" });
  }
});

module.exports = router;
