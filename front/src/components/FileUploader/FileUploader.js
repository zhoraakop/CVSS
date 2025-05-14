import React, { useState } from 'react';
import axios from 'axios';
import { Button, LinearProgress } from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import './FileUploader.css'

const FileUploader = ({ onResults }) => {
  const [loading, setLoading] = useState(false);

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    const reader = new FileReader();

    reader.onload = async (e) => {
      try {
        setLoading(true);
        const zapReport = JSON.parse(e.target.result);
        const response = await axios.post('http://localhost:5000/api/scan', zapReport);
        onResults(response.data.data); // Передаем результаты в родительский компонент
      } catch (err) {
        alert('Ошибка при анализе файла!');
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
        onChange={handleFileUpload}
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