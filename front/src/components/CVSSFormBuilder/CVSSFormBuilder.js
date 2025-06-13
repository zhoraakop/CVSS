import React, { useState, useEffect } from "react";
import {
  Warning,
  Error,
  CheckCircle,
  Info,
} from "@mui/icons-material";
import { InfoOutlined } from "@mui/icons-material";
import AddPopup from '../AddPopup/AddPopup';
import './CVSSFormBuilder.css';
import axios from "axios";

const CVSSFormBuilder = () => {
  const [tooltipOpen, setTooltipOpen] = useState(null);
  const [showPopup, setShowPopup] = useState(false);
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [openAccordion, setOpenAccordion] = useState(null);
  const toggleAccordion = (index) => {
    setOpenAccordion(openAccordion === index ? null : index);
  };
  const severityMap = {
    'Информационный': 'Информационный',
    'Низкая': 'Низкий',
    'Средняя': 'Средний',
    'Высокая': 'Высокий',
    'Критическая': 'Критический'
  };
  const [metrics, setMetrics] = useState({
    AV: "N",
    AC: "L",
    AT: "N",
    PR: "N",
    UI: "N",
    VC: "N",
    VI: "N",
    VA: "N",
    SC: "N",
    SI: "N",
    SA: "N",

    E: "X",

    CR: "X",
    IR: "X",
    AR: "X",
    MAV: "X",
    MAC: "X",
    MAT: "X",
    MPR: "X",
    MUI: "X",
    MVC: "X",
    MVI: "X",
    MVA: "X",
    MSC: "X",
    MSI: "X",
    MSA: "X",

    S: "X",
    AU: "X",
    R: "X",
    V: "X",
    RE: "X",
    U: "X",
  });

  const metricOptions = {
    AV: { N: "Сетевая", A: "Смежный", L: "Локальный", P: "Физический" },
    AC: { L: "Низкая", H: "Высокая" },
    AT: { N: "Не оказывает", P: "Существуют" },
    PR: { N: "Не оказывает", L: "Низкий", H: "Высокий" },
    UI: { N: "Не оказывает", P: "Пассивное", A: "Активное" },
    VC: { H: "Высокое", L: "Низкое", N: "Не оказывает" },
    VI: { H: "Высокое", L: "Низкое", N: "Не оказывает" },
    VA: { H: "Высокое", L: "Низкое", N: "Не оказывает" },
    SC: { H: "Высокое", L: "Низкое", N: "Не оказывает" },
    SI: { H: "Высокое", L: "Низкое", N: "Не оказывает" },
    SA: { H: "Высокое", L: "Низкое", N: "Не оказывает" },

    E: {
      X: "Не определено",
      A: "Используется в атаках",
      P: "Есть PoC-код",
      U: "Теоретическая",
    },

    CR: { X: "Не определены", H: "Высокие", M: "Средние", L: "Низкие" },
    IR: { X: "Не определены", H: "Высокие", M: "Средние", L: "Низкие" },
    AR: { X: "Не определены", H: "Высокие", M: "Средние", L: "Низкие" },
    MAV: { X: "Не определено", N: "Сетевой", A: "Смежный", L: "Локальный", P: "Физический" },
    MAC: { X: "Не определено", L: "Низкая", H: "Высокая" },
    MAT: { X: "Не определено", N: "Отсутствуют", P: "Существуют" },
    MPR: { X: "Не определено", N: "Не требуется", L: "Низкий", H: "Высокий" },
    MUI: { X: "Не определено", N: "Не требуется", P: "Пассивное", A: "Активное" },
    MVC: { X: "Не определено", H: "Высокое", L: "Низкое", N: "Не оказывает" },
    MVI: { X: "Не определено", H: "Высокое", L: "Низкое", N: "Не оказывает" },
    MVA: { X: "Не определено", H: "Высокое", L: "Низкое", N: "Не оказывает" },
    MSC: { X: "Не определено", H: "Высокое", L: "Низкое", N: "Не оказывает" },
    MSI: { X: "Не определено", S: "Угроза безопасности", H: "Высокое", L: "Низкое", N: "Не оказывает" },
    MSA: { X: "Не определено", S: "Угроза безопасности", H: "Высокое", L: "Низкое", N: "Не оказывает" },

    S: { X: "Не определено", N: "Незначительно", P: "Существенно" },
    AU: { X: "Не определена", N: "Невозможна", Y: "Возможна" },
    R: { X: "Не определено", A: "Автоматически", U: "Вручную", I: "Невозможно" },
    V: { X: "Не определены", D: "Ограниченные", C: "Множественные" },
    RE: { X: "Не определены", L: "Минимальные", M: "Умеренные", H: "Значительные" },
    U: { X: "Не определена", Clear: "Низкая", Green: "Средняя", Amber: "Высокая", Red: "Критическая" },
  };

  const handleMetricChange = (metric, value) => {
    setMetrics((prev) => ({ ...prev, [metric]: value }));
  };

  const validateCVSS4Vector = (vector) => {
    if (!vector.startsWith('CVSS:4.0/')) {
      return false;
    }
    const parts = vector.split('/').slice(1);
    if (parts.length < 11) {
      return false;
    }
    return true;
  };

  const buildVector = () => {
    const requiredMetrics = [
      `AV:${metrics.AV}`,
      `AC:${metrics.AC}`,
      `AT:${metrics.AT}`,
      `PR:${metrics.PR}`,
      `UI:${metrics.UI}`,
      `VC:${metrics.VC}`,
      `VI:${metrics.VI}`,
      `VA:${metrics.VA}`,
      `SC:${metrics.SC}`,
      `SI:${metrics.SI}`,
      `SA:${metrics.SA}`
    ];
    const optionalMetrics = Object.entries(metrics)
      .filter(([metric]) => ![
        'AV', 'AC', 'AT', 'PR', 'UI', 
        'VC', 'VI', 'VA', 'SC', 'SI', 'SA'
      ].includes(metric))
      .filter(([_, value]) => value && value !== "X")
      .map(([metric, value]) => `${metric}:${value}`);

    const vector = `CVSS:4.0/${[...requiredMetrics, ...optionalMetrics].join('/')}`;
    return vector.endsWith('/') ? vector.slice(0, -1) : vector;
  };

  const handleEvaluate = async () => {
    setIsLoading(true);
    try {
      const vector = buildVector();
      console.log("Generated vector:", vector);
      
      if (!validateCVSS4Vector(vector)) {
        throw new Error("Invalid CVSS 4.0 vector format");
      }

      const response = await axios.post(
        'http://localhost:5000/api/evaluate',
        { vector },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );

      setResult(response.data);
    } catch (err) {
      console.error("CVSS calculation error:", err);
      setResult({
        success: false,
        error: err.response?.data?.error || err.message,
        details: err.response?.data,
        vector: buildVector()
      });
    } finally {
      setIsLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "Отсутствует": return "grey";
      case "Низкая": return "green";
      case "Средняя": return "orange";
      case "Высокая": return "red";
      case "Критическая": return "darkred";
      default: return "black";
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case "Отсутствует": return <Info color="info" />;
      case "Низкая": return <CheckCircle color="success" />;
      case "Средняя": return <Warning color="warning" />;
      case "Высокая": return <Error color="error" />;
      case "Критическая": return <Error color="error" />;
      default: return <Info color="info" />;
    }
  };

  const handleCopyVector = () => {
    navigator.clipboard.writeText(buildVector());
  };

  const getMetricLabel = (metric) => {
    const labels = {
      AV: "Вектор атаки(AV)",
      AC: "Сложность атаки(AC)",
      AT: "Требования к атаке(AT)", 
      PR: "Уровень привилегий(PR)",
      UI: "Взаимодействие с пользователем(UI)",
      VC: "Влияние на конфиденциальность(VC)",
      VI: "Влияние на целостность(VI)",
      VA: "Влияние на доступность(VA)",
      SC: "Влияние на конфиденциальность(SC)",
      SI: "Влияние на целостность(SI)",
      SA: "Влияние на доступность(SA)",

      E: "Доступность средств эксплуатации(E)",

      CR: "Требования к конфиденциальности(CR)",
      IR: "Требования к целостности(IR)",
      AR: "Требования к доступности(AR)",
      MAV: "Вектор атаки (корр.)(MAV)",
      MAC: "Сложность атаки (корр.)(MAC)",
      MAT: "Требования к атаке (корр.)(MAT)",
      MPR: "Уровень привилегий (корр.)(MPR)",
      MUI: "Взаимодействие с пользователем (корр.)(MUI)",
      MVC: "Влияние на конфиденциальность (корр.)(MVC)",
      MVI: "Влияние на целостность (корр.)(MVI)",
      MVA: "Влияние на доступность (корр.)(MVA)",
      MSC: "Влияние на конфиденциальность (корр.)(MSC)",
      MSI: "Влияние на целостность (корр.)(MSI)",
      MSA: "Влияние на доступность (корр.)(MSA)",

      S: "Влияние на безопасность(S)",
      AU: "Автоматизация эксплуатации(AU)",
      R: "Восстановление работоспособности(R)",
      V: "Ресурсы, получаемые с помощью одного события эксплуатации(V)",
      RE: "Усилия по реагированию на уязвимость(RE)",
      U: "Срочность исправления(U)"
    };
    return labels[metric] || metric;
  };


  const renderMetricButtons = (metric) => (
    <div key={metric} className="metric-button-group">
      <div className="metric-label">{getMetricLabel(metric)}</div>
      <div className="metric-button-row">
        {Object.entries(metricOptions[metric]).map(([value, label]) => (
          <button
            key={value}
            className={`metric-option-button ${
              metrics[metric] === value ? "selected" : ""
            }`}
            onClick={() => handleMetricChange(metric, value)}
          >
            {label} ({value})
          </button>
        ))}
      </div>
    </div>
  );

  const metricGroups = [
    {
      title: "Базовые метрики",
      subgroups: [
        {
          title: "Показатели возможности эксплуатации",
          description: "Характеристики, описывающие условия и сложность эксплуатации уязвимости",
          metrics: ["AV", "AC", "AT", "PR", "UI"]
        },
        {
          title: "Показатели воздействия на уязвимую систему",
          description: "Последствия успешной эксплуатации для атакуемой системы",
          metrics: ["VC", "VI", "VA"]
        },
        {
          title: "Показатели воздействия на последующие системы",
          description: "Возможные последствия для связанных систем после компрометации",
          metrics: ["SC", "SI", "SA"]
        }
      ],
      description: "Основные характеристики уязвимости, неизменные во времени и в разных средах"
    },
    {
      title: "Метрики угроз",
      metrics: ["E"],
      description: "Вероятность эксплуатации уязвимости на основе текущего состояния угроз"
    },
    {
      title: "Контекстные метрики",
      subgroups: [
        {
          title: "Требования безопасности",
          description: "Критичность защищаемых активов в конкретной среде",
          metrics: ["CR", "IR", "AR"]
        },
        {
          title: "Модифицированные базовые метрики(Показатели возможности эксплуатации)",
          description: "Корректировка базовых показателей для конкретной среды",
          metrics: ["MAV", "MAC", "MAT", "MPR", "MUI"]
        },
        {
          title: "Модифицированные базовые метрики(Показатели воздействия на уязвимую систему)",
          description: "Корректировка базовых показателей для конкретной среды",
          metrics: ["MVC", "MVI", "MVA"]
        },
        {
          title: "Модифицированные базовые метрики(Показатели воздействия на последующие системы)",
          description: "Корректировка базовых показателей для конкретной среды",
          metrics: ["MSC", "MSI", "MSA"]
        }
      ],
      description: "Характеристики, уникальные для конкретной среды функционирования"
    },
     {
      title: "Дополнительные метрики",
      metrics: ["S", "AU", "R", "V", "RE", "U"],
      description: "Метрики отражают контекст, а также описывают и измеряют дополнительные внешние атрибуты уязвимости."
    },
  ];


  useEffect(() => {
    const handleClickOutside = () => setTooltipOpen(null);
    document.addEventListener("click", handleClickOutside);
    return () => document.removeEventListener("click", handleClickOutside);
  }, []);

  return (
    <div className="cvss-container">
      <h2 className="form-title">Калькулятор для вычисления CVSS оценки (версия 4.0)</h2>
      <div className="form-box">
        {metricGroups.map((group, index) => (
          <div className="metric-accordion" key={group.title}>
            <div className="accordion-summary" onClick={() => toggleAccordion(index)}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", position: "relative" }}>
                <h3 className="metric-section-title">{group.title}</h3>
                <div className="tooltip-wrapper">
                  <button
                    className="info-button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setTooltipOpen(tooltipOpen === index ? null : index);
                    }}
                    title="Информация"
                  >
                    <InfoOutlined style={{ fontSize: "16px", color: "#1976d2" }} />
                  </button>

                  {tooltipOpen === index && (
                    <div className="tooltip-box" onClick={(e) => e.stopPropagation()}>
                      <strong>{group.title}</strong>
                      <p>{group.description}</p>
                    </div>
                  )}
                </div>
              </div>
              <span className="accordion-icon">{openAccordion === index ? "▲" : "▼"}</span>
            </div>
            
            {openAccordion === index && (
              <div className="accordion-details">
                {group.subgroups ? (
                  group.subgroups.map((subgroup, subIndex) => (
                    <div key={subIndex} className="subgroup-container">
                      <h4 className="subgroup-title">
                        {subgroup.title}
                      </h4>
                      <div className="metric-grid">
                        {subgroup.metrics.map((metric) => renderMetricButtons(metric))}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="metric-grid">
                    {group.metrics.map((metric) => renderMetricButtons(metric))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}

        <div className="button-wrapper">
          <button className="submit-button" onClick={handleEvaluate} disabled={isLoading}>
            {isLoading ? "Идет рассчет..." : "Рассчитать CVSS"}
          </button>
        </div>
      </div>
      
      {result && (
      <div className="result-box">
        {result.success ? (
          <>
            <div className="vector-row">
              <div className="vector-text">
                <strong>Вектор:</strong> {result.vector}
              </div>
              <button className="copy-button" onClick={handleCopyVector}>
                📋 Копировать
              </button>
            </div>

            <div className="score-section">
              {getSeverityIcon(result.severity)}
              <div className="severity-chip" style={{ backgroundColor: getSeverityColor(result.severity) }}>
                {result.severity}
              </div>
              <div className="score-text">
                <strong>Оценка:</strong> {result.score.toFixed(1)}
              </div>
              <div className="addButton-wrapper">
                <button className="add-button" onClick={() => setShowPopup(true)}>
                  Добавить уязвимость
                </button>
              </div>
            </div>


            {showPopup && (
              <AddPopup
                onClose={() => setShowPopup(false)}
                cvssVector={result.vector}
                cvssScore={result.score}
                riskLevel={severityMap[result.severity]}
              />
            )}
          </>
        ) : (
          <>
            <h4 className="error-title">Ошибка:</h4>
            <p className="error-text">{result.error}</p>
            {result.details?.receivedVector && (
              <code>Отправленный вектор: {result.details.receivedVector}</code>
            )}
            {result.details?.example && (
              <code>Пример вектора: {result.details.example}</code>
            )}
            {result.vector && <code>Сгенерированный вектор: {result.vector}</code>}
          </>
        )}
      </div>
    )}
    </div>
  );
};


export default CVSSFormBuilder;