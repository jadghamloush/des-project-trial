import React, { useEffect, useState } from 'react';
import {
  Table,
  Card,
  Spinner,
  Alert,
  Pagination,
  Modal,
  InputGroup,
  FormControl,
  Button,
  Toast,
  ToastContainer,
} from 'react-bootstrap';
import axios from 'axios';
import './HistoryView.css';
import { FaFilter, FaSearch } from 'react-icons/fa'; // Removed FaFileDownload and FaCopy

const operationDisplayNames = {
  encrypt: 'Encrypt',
  decrypt: 'Decrypt',
  generate_key: 'Generate Key',
};

const operationBadgeClasses = {
  encrypt: 'encrypt',
  decrypt: 'decrypt',
  generate_key: 'generate-key',
};

const HistoryView = () => {
  const [history, setHistory] = useState([]);
  const [filteredHistory, setFilteredHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const entriesPerPage = 20;

  // Filtering state
  const [filterOperation, setFilterOperation] = useState('All');

  // Search state
  const [searchTerm, setSearchTerm] = useState('');

  // Modal states
  const [showModal, setShowModal] = useState(false);
  const [modalContent, setModalContent] = useState('');

  // Toast states for non-intrusive notifications
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  useEffect(() => {
    fetchHistory();
  }, []);

  useEffect(() => {
    applyFilters();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [history, filterOperation, searchTerm]);

  const fetchHistory = async () => {
    try {
      const response = await axios.get('http://localhost:5000/history');
      if (response.data.success) {
        setHistory(response.data.history);
      } else {
        setError(response.data.message || 'Failed to fetch history.');
      }
    } catch (err) {
      setError('An error occurred while fetching history.');
      console.error(err);
    }
    setLoading(false);
  };

  const applyFilters = () => {
    let updatedHistory = [...history];

    // Filter by operation
    if (filterOperation !== 'All') {
      updatedHistory = updatedHistory.filter(
        (entry) =>
          entry.operation &&
          entry.operation.toLowerCase() === filterOperation.toLowerCase().replace(' ', '_')
      );
    }

    // Search by key, input, or output
    if (searchTerm.trim() !== '') {
      updatedHistory = updatedHistory.filter(
        (entry) =>
          (entry.key_hex && entry.key_hex.toLowerCase().includes(searchTerm.toLowerCase())) ||
          (entry.input_hex && entry.input_hex.toLowerCase().includes(searchTerm.toLowerCase())) ||
          (entry.output_hex && entry.output_hex.toLowerCase().includes(searchTerm.toLowerCase())) ||
          (entry.output_text && entry.output_text.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }

    setFilteredHistory(updatedHistory);
    setCurrentPage(1); // Reset to first page after filtering
  };

  // Calculate pagination
  const indexOfLastEntry = currentPage * entriesPerPage;
  const indexOfFirstEntry = indexOfLastEntry - entriesPerPage;
  const currentEntries = filteredHistory.slice(indexOfFirstEntry, indexOfLastEntry);
  const totalPages = Math.ceil(filteredHistory.length / entriesPerPage);

  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  const handleFilterSelect = (operation) => {
    setFilterOperation(operation);
  };

  const handleSearchChange = (e) => {
    setSearchTerm(e.target.value);
  };

  const handleViewFile = (data) => {
    setModalContent(data);
    setShowModal(true);
  };

  return (
    <div className="history-view-container">
      <Card className="shadow-lg p-4 history-card">
        <h2 className="text-center text-primary mb-4">Operation History</h2>

        {/* Filters and Search */}
        <div className="filters-search-container">
          <InputGroup className="search-bar">
            <InputGroup.Text>
              <FaSearch />
            </InputGroup.Text>
            <FormControl
              placeholder="Search by Key, Input, or Output"
              value={searchTerm}
              onChange={handleSearchChange}
            />
          </InputGroup>

          <div className="filter-buttons">
            <Button
              variant={filterOperation === 'All' ? 'primary' : 'outline-primary'}
              onClick={() => handleFilterSelect('All')}
            >
              All Operations
            </Button>
            <Button
              variant={filterOperation === 'Encrypt' ? 'danger' : 'outline-danger'}
              onClick={() => handleFilterSelect('Encrypt')}
            >
              Encrypt
            </Button>
            <Button
              variant={filterOperation === 'Decrypt' ? 'success' : 'outline-success'}
              onClick={() => handleFilterSelect('Decrypt')}
            >
              Decrypt
            </Button>
            <Button
              variant={filterOperation === 'Generate Key' ? 'info' : 'outline-info'}
              onClick={() => handleFilterSelect('Generate Key')}
            >
              Generate Key
            </Button>
          </div>
        </div>

        {loading ? (
          <div className="d-flex justify-content-center my-5">
            <Spinner animation="border" variant="primary" />
          </div>
        ) : error ? (
          <Alert variant="danger" className="text-center">
            {error}
          </Alert>
        ) : filteredHistory.length === 0 ? (
          <Alert variant="info" className="text-center">
            No history available.
          </Alert>
        ) : (
          <>
            <Table striped bordered hover responsive>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Operation</th>
                  <th>Timestamp</th>
                  <th>Key (Hex)</th>
                  <th>Input (Hex)</th>
                  <th>Output (Hex)</th>
                  <th>Output (Text)</th>
                  <th>Time Taken (ms)</th>
                </tr>
              </thead>
              <tbody>
                {currentEntries.map((entry, index) => (
                  <tr key={entry.id}>
                    <td>{indexOfFirstEntry + index + 1}</td>
                    <td>
                      <span
                        className={`badge operation-badge ${
                          entry.operation
                            ? operationBadgeClasses[entry.operation.toLowerCase()] || 'unknown'
                            : 'unknown'
                        }`}
                      >
                        {entry.operation
                          ? operationDisplayNames[entry.operation.toLowerCase()] || 'Unknown'
                          : 'Unknown'}
                      </span>
                    </td>
                    <td>
                      {entry.timestamp
                        ? new Date(entry.timestamp).toLocaleString()
                        : 'N/A'}
                    </td>
                    <td>{entry.key_hex || 'N/A'}</td>
                    <td>{entry.input_hex || 'N/A'}</td>
                    <td>{entry.output_hex || 'N/A'}</td>
                    <td>{entry.output_text || 'N/A'}</td>
                    <td>{entry.time_taken ? entry.time_taken.toFixed(2) : 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </Table>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <Pagination className="justify-content-center">
                <Pagination.First onClick={() => paginate(1)} disabled={currentPage === 1} />
                <Pagination.Prev onClick={() => paginate(currentPage - 1)} disabled={currentPage === 1} />
                {[...Array(totalPages)].map((_, idx) => (
                  <Pagination.Item
                    key={idx + 1}
                    active={idx + 1 === currentPage}
                    onClick={() => paginate(idx + 1)}
                  >
                    {idx + 1}
                  </Pagination.Item>
                ))}
                <Pagination.Next onClick={() => paginate(currentPage + 1)} disabled={currentPage === totalPages} />
                <Pagination.Last onClick={() => paginate(totalPages)} disabled={currentPage === totalPages} />
              </Pagination>
            )}
          </>
        )}

        {/* Modal for Viewing File Content */}
        <Modal show={showModal} onHide={() => setShowModal(false)} size="lg" centered>
          <Modal.Header closeButton>
            <Modal.Title>File Content</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <pre>{modalContent}</pre>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => setShowModal(false)}>
              Close
            </Button>
          </Modal.Footer>
        </Modal>

        {/* Toast Notifications */}
        <ToastContainer position="bottom-end" className="p-3">
          <Toast onClose={() => setShowToast(false)} show={showToast} delay={3000} autohide bg="success">
            <Toast.Body>{toastMessage}</Toast.Body>
          </Toast>
        </ToastContainer>
      </Card>
    </div>
  );
};

export default HistoryView;
