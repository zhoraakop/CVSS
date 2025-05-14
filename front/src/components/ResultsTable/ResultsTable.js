import React from 'react';
import './ResultsTable.css';

const ResultsTable = ({ data }) => (
  <div className="table-container">
    <table className="results-table">
      <thead>
        <tr>
          <th>Уязвимость</th>
          <th>Риск</th>
          <th>CVSS</th>
          <th>Рекомендация</th>
        </tr>
      </thead>
      <tbody>
        {data.map((row, index) => (
          <tr key={index}>
            <td>{row.name || row.alert || row.originalName || 'Без названия'}</td>
            <td className={`risk ${row.risk?.toLowerCase()}`}>
              {row.risk}
            </td>
            <td>
              {row.cvssScore !== undefined
                ? `${row.cvssScore} (${row.cvssSeverity})`
                : '—'}
            </td>
            <td>{row.recommendation}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

export default ResultsTable;
