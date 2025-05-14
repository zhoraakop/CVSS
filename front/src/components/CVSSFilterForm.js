import React, { useState } from 'react';
import { TextField, Button, Box } from '@mui/material';
import axios from 'axios';

const CVSSFilterForm = () => {
  const [vector, setVector] = useState('');
  const [result, setResult] = useState(null);

  const handleEvaluate = async () => {
    try {
      const response = await axios.post('http://localhost:5000/api/evaluate', { vector });
      setResult(response.data);
    } catch (err) {
      console.error(err);
      alert('Ошибка при расчете CVSS!');
    }
  };

  return (
    <Box sx={{ mt: 5 }}>
      <TextField
        label="CVSS Vector (например, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
        value={vector}
        onChange={(e) => setVector(e.target.value)}
        fullWidth
        variant="outlined"
      />
      <Button sx={{ mt: 2 }} variant="contained" onClick={handleEvaluate}>
        Выполнить расчет
      </Button>
      {result && (
        <Box sx={{ mt: 3 }}>
          <div><strong>Оценка:</strong> {result.score}</div>
          <div><strong>Уровень:</strong> {result.severity}</div>
        </Box>
      )}
    </Box>
  );
};

export default CVSSFilterForm;
