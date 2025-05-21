import React, { useState } from 'react';
import axios from 'axios';
import { Button, LinearProgress } from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import './FileUploader.css'

const FileUploader = ({ onResults }) => {
  const [loading, setLoading] = useState(false);

  const handleFileUpload = (e) => {
  const file = e.target.files[0];

  if (!file) return;

  const isJsonFile = file.name.toLowerCase().endsWith('.json') || file.type === 'application/json';

  if (!isJsonFile) {
    alert('Ошибка: Пожалуйста, загрузите файл в формате JSON.');
    return;
  }

  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      setLoading(true);
      const zapReport = JSON.parse(e.target.result); // может выбросить ошибку
      const response = await axios.post('http://localhost:5000/api/scan', zapReport);
      onResults(response.data.data);
    } catch (err) {
      alert('Ошибка при анализе файла! Убедитесь, что это корректный JSON.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  reader.readAsText(file);
  };

  return (
    <div className='container'>
      <input
        type="file"
        accept=".json"
        onChange={(e) => {
          handleFileUpload(e);
          e.target.value = null;
        }}
        id="upload-file"
        hidden
      />
      <label htmlFor="upload-file">
        <Button
          variant="contained"
          component="span"
          startIcon={<CloudUploadIcon />}
          disabled={loading}
        >
          Загрузить отчёт ZAP
        </Button>
      </label>
      {loading && <LinearProgress sx={{ mt: 2 }} />}
    </div>
  );
};

export default FileUploader;