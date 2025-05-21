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
          <th>Ссылки</th>
        </tr>
      </thead>
      <tbody>
        {data.map((row, index) => {
          let cleanedLinks = [];
          if (row.reference) {
            cleanedLinks = row.reference
              .split(/<\/?p>/gi)
              .map(ref => ref.trim())
              .filter(ref => ref && ref.startsWith('http'));
          }

          return (
            <tr key={index}>
              <td>{row.name || row.alert || row.originalName || 'Без названия'}</td>
              <td className={`risk ${row.risk?.toLowerCase()}`}>{row.risk}</td>
              <td>
                {row.cvssScore !== undefined
                  ? `${row.cvssScore} (${row.cvssSeverity})`
                  : '—'}
              </td>
              <td>{row.recommendation}</td>
              <td>
                {cleanedLinks.length > 0 ? (
                  cleanedLinks.map((link, i) => (
                    <a
                      key={i}
                      href={link}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ marginRight: '6px' }}
                    >
                      [{i + 1}]
                    </a>
                  ))
                ) : (
                  '—'
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);


export default ResultsTable;
