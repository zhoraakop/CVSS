import React, { useState } from 'react';
import FileUploader from './components/FileUploader/FileUploader';
import ResultsTable from './components/ResultsTable/ResultsTable';
import CVSSFormBuilder from './components/CVSSFormBuilder/CVSSFormBuilder';
import './App.css'; // Создайте этот файл для стилей

function App() {
  const [results, setResults] = useState([]);

  return (
    <div className="app-container">
      <h1 className="app-title">Анализатор уязвимостей</h1>
      
      <CVSSFormBuilder />
      
      <FileUploader onResults={setResults} className="file-uploader" />
      
      {results.length > 0 && (
        <ResultsTable data={results} className="results-table" />
      )}
    </div>
  );
}

export default App;