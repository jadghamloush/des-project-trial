// src/components/ReportGeneration.jsx

import React, { useState } from 'react';
import { Button, Spinner, Alert } from 'react-bootstrap';
import axios from 'axios';
import PropTypes from 'prop-types';
import './ReportGeneration.css';

const ReportGeneration = ({ reportData }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const downloadReport = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.post(
        'https://flask-alb-1611654522.us-east-2.elb.amazonaws.com/generate_report',
        reportData,
        { responseType: 'blob' } // Important for handling binary data
      );

      // Create a URL for the PDF blob
      const url = window.URL.createObjectURL(
        new Blob([response.data], { type: 'application/pdf' })
      );
      const link = document.createElement('a');
      link.href = url;

      // Extract timestamp from reportData or use current time
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      link.setAttribute('download', `${reportData.reportType}_Report_${timestamp}.pdf`);
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
    roundDetails: PropTypes.arrayOf(
      PropTypes.shape({
        round: PropTypes.number.isRequired,
        subkey: PropTypes.arrayOf(PropTypes.number).isRequired,
        left_before: PropTypes.arrayOf(PropTypes.number).isRequired,
        right_before: PropTypes.arrayOf(PropTypes.number).isRequired,
        expanded_right: PropTypes.arrayOf(PropTypes.number).isRequired,
        xor_with_subkey: PropTypes.arrayOf(PropTypes.number).isRequired,
        sbox_details: PropTypes.arrayOf(
          PropTypes.shape({
            column: PropTypes.number.isRequired,
            input: PropTypes.string.isRequired,
            output: PropTypes.string.isRequired,
            row: PropTypes.number.isRequired,
            sbox: PropTypes.string.isRequired,
          })
        ).isRequired,
        permutation_output: PropTypes.arrayOf(PropTypes.number).isRequired,
        left_after: PropTypes.arrayOf(PropTypes.number).isRequired,
        right_after: PropTypes.arrayOf(PropTypes.number).isRequired,
        sbox_output: PropTypes.string.isRequired, // Added sbox_output
      })
    ).isRequired,
    timeTaken: PropTypes.number.isRequired,
    resultHex: PropTypes.string.isRequired,
    keyHex: PropTypes.string,
    keyBinary: PropTypes.string,
    keyBase64: PropTypes.string,
  }).isRequired,
};

export default ReportGeneration;
