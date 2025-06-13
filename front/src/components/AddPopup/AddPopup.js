import React, { useState } from 'react';
import './AddPopup.css'; // если нужно стилизовать

const AddVulnerabilityPopup = ({ onClose, cvssVector, cvssScore, riskLevel }) => {
  const [formData, setFormData] = useState({
    zapPluginId: '',
    name: '',
    description: '',
    recommendation: ''
  });

  const [message, setMessage] = useState('');

  const handleChange = (e) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const payload = {
      ...formData,
      cvssVector,
      cvssScore,
      riskLevel
    };

    try {
      const res = await fetch('http://localhost:5000/api/vulnerabilities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();

      if (data.success) {
        setMessage('✅ Уязвимость успешно добавлена!');
        setTimeout(() => {
          onClose();
        }, 1500);
      } else {
        setMessage(`❌ Ошибка: ${data.message}`);
      }
    } catch (err) {
      console.error(err);
      setMessage('❌ Ошибка при отправке данных.');
    }
  };

  return (
    <div className="popup-backdrop">
      <div className="popup">
        <h2>Добавить уязвимость</h2>
        <form onSubmit={handleSubmit}>
          <label>
            zapPluginId:
            <input type="text" name="zapPluginId" value={formData.zapPluginId} onChange={handleChange} required />
          </label>
          <label>
            Название:
            <input type="text" name="name" value={formData.name} onChange={handleChange} required />
          </label>
          <label>
            Описание:
            <textarea name="description" value={formData.description} onChange={handleChange} />
          </label>
          <label>
            Рекомендации:
            <textarea name="recommendation" value={formData.recommendation} onChange={handleChange} required />
          </label>

          <div className="readonly">
            <p><strong>CVSS Вектор:</strong> {cvssVector}</p>
            <p><strong>CVSS Оценка:</strong> {cvssScore}</p>
            <p><strong>Уровень риска:</strong> {riskLevel}</p>
          </div>

          <div className="popup-actions">
            <button className="save-button" onClick={handleSubmit}>Добавить</button>
            <button className="cancel-button" onClick={onClose}>Отмена</button>
          </div>
          {message && <p className="message">{message}</p>}
        </form>
      </div>
    </div>
  );
};

export default AddVulnerabilityPopup;
