// src/components/ReportGeneration.jsx
import React, { useState } from 'react';
import { Button, Spinner, Alert } from 'react-bootstrap';
import axios from 'axios';
import PropTypes from 'prop-types';
import './ReportGeneration.css';


const API_URL = process.env.REACT_APP_API_URL;


const ReportGeneration = ({ reportData }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const downloadReport = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.post(
        `${API_URL}/generate_report`,
        reportData,
        { responseType: 'blob' } // Important for handling binary data
      );

      // Create a URL for the PDF blob
      const url = window.URL.createObjectURL(
        new Blob([response.data], { type: 'application/pdf' })
      );
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${reportData.reportType}_Report.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      setError(
        err.response?.data?.message || 'Failed to generate report.'
      );
      console.error(err);
    }
    setLoading(false);
  };

  return (
    <div className="mt-3">
      {error && <Alert variant="danger">{error}</Alert>}
      <Button variant="secondary" onClick={downloadReport} disabled={loading}>
        {loading ? (
          <>
            <Spinner
              as="span"
              animation="border"
              size="sm"
              role="status"
              aria-hidden="true"
              className="me-2"
            />
            Generating Report...
          </>
        ) : (
          'Download PDF Report'
        )}
      </Button>
    </div>
  );
};

ReportGeneration.propTypes = {
  reportData: PropTypes.shape({
    reportType: PropTypes.string.isRequired,
    roundDetails: PropTypes.array.isRequired,
    timeTaken: PropTypes.number.isRequired,
    resultHex: PropTypes.string.isRequired,
  }).isRequired,
};

export default ReportGeneration;
