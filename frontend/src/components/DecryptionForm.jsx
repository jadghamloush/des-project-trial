// frontend/src/components/DecryptionForm.jsx

import React, { useState } from 'react';
import {
  Button,
  Form,
  Card,
  InputGroup,
  FormControl,
  Alert,
  Spinner,
} from 'react-bootstrap';
import RoundDetails from './RoundDetails';
import ReportGeneration from './ReportGeneration';
import axios from 'axios';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import './DecryptionForm.css';
import { hexToBin, hexToBytes } from '../utils/conversions'; // Import utility functions

const DecryptionForm = () => {
  const [decryptedText, setDecryptedText] = useState('');
  const [decryptedHex, setDecryptedHex] = useState('');
  const [roundDetails, setRoundDetails] = useState([]);
  const [timeTaken, setTimeTaken] = useState(0);
  const [error, setError] = useState('');
  const [reportData, setReportData] = useState(null);

  const formik = useFormik({
    initialValues: {
      ciphertext: '',
      key: '',
      inputFormat: 'hex', // Default input format
      file: null,
    },
    validationSchema: Yup.object({
      inputFormat: Yup.string()
        .oneOf(['hex', 'text', 'binary', 'file'], 'Invalid input format')
        .required('Input format is required'),
      key: Yup.string()
        .matches(/^[0-9a-fA-F]{16}$/, 'Key must be exactly 16 hexadecimal characters')
        .required('Key is required'),
      ciphertext: Yup.string().when('inputFormat', (inputFormat, schema) => {
        switch (inputFormat) {
          case 'hex':
            return schema
              .required('Ciphertext is required')
              .matches(/^[0-9a-fA-F]{16}$/, 'Invalid hexadecimal format');
          case 'binary':
            return schema
              .required('Ciphertext is required')
              .matches(/^[01]{64}$/, 'Invalid binary format');
          case 'text':
            return schema
              .required('Ciphertext is required')
              .min(1, 'Ciphertext cannot be empty');
          default:
            return schema.notRequired();
        }
      }),
      file: Yup.mixed().when('inputFormat', (inputFormat, schema) => {
        if (inputFormat === 'file') {
          return schema
            .required('File is required')
            .test('fileFormat', 'Only .txt files are allowed', (value) => {
              if (value) {
                return ['text/plain'].includes(value.type);
              }
              return false;
            })
            .test('fileSize', 'File size too large (Max: 1MB)', (value) => {
              if (value) {
                return value.size <= 1 * 1024 * 1024; // 1MB
              }
              return false;
            });
        }
        return schema.notRequired();
      }),
    }),
    onSubmit: async (values, { setSubmitting }) => {
      setError('');
      setDecryptedText('');
      setDecryptedHex('');
      setRoundDetails([]);
      setTimeTaken(0);
      setReportData(null);

      try {
        let formData = new FormData();
        formData.append('key', values.key);
        formData.append('input_format', values.inputFormat);

        if (values.inputFormat === 'file') {
          formData.append('ciphertext', values.file);
        } else {
          formData.append('ciphertext', values.ciphertext);
        }

        const config = {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        };

        const response = await axios.post('https://flask-alb-1611654522.us-east-2.elb.amazonaws.com/decrypt', formData, config);

        if (response.data.success) {
          setDecryptedHex(response.data.decrypted_hex);
          setDecryptedText(response.data.decrypted_text);
          setRoundDetails(response.data.round_details);
          setTimeTaken(response.data.time_taken);

          // Process round_details to include sbox_output
          const processedRoundDetails = response.data.round_details.map((round) => {
            const sbox_output = round.sbox_details
              .map((sbox) => `${sbox.sbox}:${sbox.output}`)
              .join(', ');
            return { ...round, sbox_output };
          });

          // Prepare key information
          const keyHex = values.key;
          const keyBinary = hexToBin(values.key);
          const keyBytes = hexToBytes(values.key);
          const keyBase64 = btoa(String.fromCharCode(...keyBytes));

          setReportData({
            reportType: 'Decryption',
            roundDetails: processedRoundDetails,
            timeTaken: response.data.time_taken,
            resultHex: response.data.decrypted_hex,
            keyHex: keyHex,
            keyBinary: keyBinary,
            keyBase64: keyBase64,
          });
        } else {
          setError(response.data.message || 'Decryption failed.');
        }
      } catch (error) {
        setError(error.response?.data?.message || 'An error occurred during decryption.');
        console.error(error);
      }

      setSubmitting(false);
    },
  });

  return (
    <div className="decryption-form-container">
      <Card className="shadow-lg p-5 decryption-card">
        <h2 className="text-center text-primary mb-4">DES Decryption</h2>
        <Form onSubmit={formik.handleSubmit}>
          {/* Input Format Selection */}
          <Form.Group controlId="inputFormat" className="mb-4">
            <Form.Label>Input Format</Form.Label>
            <Form.Control
              as="select"
              name="inputFormat"
              value={formik.values.inputFormat}
              onChange={(e) => {
                formik.handleChange(e);
                // Reset ciphertext and file when input format changes
                formik.setFieldValue('ciphertext', '');
                formik.setFieldValue('file', null);
              }}
              onBlur={formik.handleBlur}
              isInvalid={formik.touched.inputFormat && formik.errors.inputFormat}
              className="input-select"
            >
              <option value="hex">Hexadecimal</option>
              <option value="text">ASCII Text</option>
              <option value="binary">Binary</option>
              <option value="file">File Upload (.txt)</option>
            </Form.Control>
            {formik.touched.inputFormat && formik.errors.inputFormat ? (
              <Form.Control.Feedback type="invalid">
                {formik.errors.inputFormat}
              </Form.Control.Feedback>
            ) : null}
          </Form.Group>

          {/* Conditional Rendering Based on Input Format */}
          {formik.values.inputFormat !== 'file' ? (
            <Form.Group controlId="ciphertext" className="mb-4">
              <Form.Label>
                {formik.values.inputFormat === 'hex'
                  ? 'Ciphertext (16 Hex Characters)'
                  : formik.values.inputFormat === 'text'
                  ? 'Ciphertext (ASCII Text)'
                  : 'Ciphertext (64 Binary Bits)'}
              </Form.Label>
              <Form.Control
                type="text"
                name="ciphertext"
                value={formik.values.ciphertext}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                placeholder={
                  formik.values.inputFormat === 'hex'
                    ? 'Enter ciphertext in hexadecimal'
                    : formik.values.inputFormat === 'text'
                    ? 'Enter ASCII ciphertext'
                    : 'Enter binary ciphertext string (64 bits)'
                }
                isInvalid={formik.touched.ciphertext && formik.errors.ciphertext}
                className="input-field"
              />
              {formik.touched.ciphertext && formik.errors.ciphertext ? (
                <Form.Control.Feedback type="invalid">
                  {formik.errors.ciphertext}
                </Form.Control.Feedback>
              ) : null}
            </Form.Group>
          ) : (
            <Form.Group controlId="file" className="mb-4">
              <Form.Label>Upload File (.txt)</Form.Label>
              <Form.Control
                type="file"
                name="file"
                accept=".txt"
                onChange={(event) => {
                  formik.setFieldValue('file', event.currentTarget.files[0]);
                }}
                onBlur={formik.handleBlur}
                isInvalid={formik.touched.file && formik.errors.file}
                className="input-file"
              />
              {formik.touched.file && formik.errors.file ? (
                <Form.Control.Feedback type="invalid">
                  {formik.errors.file}
                </Form.Control.Feedback>
              ) : null}
            </Form.Group>
          )}

          {/* Key Input */}
          <Form.Group controlId="key" className="mb-4">
            <Form.Label>Key (16 Hex Characters)</Form.Label>
            <InputGroup>
              <FormControl
                type="text"
                name="key"
                value={formik.values.key}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                placeholder="Enter key in hexadecimal"
                isInvalid={formik.touched.key && formik.errors.key}
                className="input-field"
              />
              <Button
                variant="outline-secondary"
                onClick={() => formik.setFieldValue('key', '')}
                className="clear-btn"
                type="button" // Ensure it's a button to prevent form submission
              >
                Clear
              </Button>
              {formik.touched.key && formik.errors.key ? (
                <Form.Control.Feedback type="invalid">
                  {formik.errors.key}
                </Form.Control.Feedback>
              ) : null}
            </InputGroup>
          </Form.Group>

          {/* Error Message */}
          {error && <Alert variant="danger">{error}</Alert>}

          {/* Submit Button */}
          <Button
            variant="primary"
            type="submit"
            className="submit-btn"
            disabled={formik.isSubmitting}
          >
            {formik.isSubmitting ? (
              <>
                <Spinner
                  as="span"
                  animation="border"
                  size="sm"
                  role="status"
                  aria-hidden="true"
                  className="me-2"
                />
                Decrypting...
              </>
            ) : (
              'Decrypt'
            )}
          </Button>
        </Form>

        {/* Decrypted Data Display */}
        {(decryptedHex || decryptedText) && (
          <div className="mt-4">
            {decryptedHex && (
              <h4 className="decrypted-hex">
                Decrypted Hex: <span>{decryptedHex}</span>
              </h4>
            )}
            {decryptedText && (
              <h4 className="decrypted-text">
                Decrypted Text: <span>{decryptedText}</span>
              </h4>
            )}
            <h5>Time Taken: {timeTaken} milliseconds</h5>
            <RoundDetails rounds={roundDetails} />
            {reportData && <ReportGeneration reportData={reportData} />}
          </div>
        )}
      </Card>
    </div>
  );
};

export default DecryptionForm;
