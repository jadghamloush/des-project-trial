import React from 'react';
import { Card, Button } from 'react-bootstrap';
import { Link } from 'react-router-dom';
import { FaKey, FaLock, FaTachometerAlt } from 'react-icons/fa';
import './Home.css';

const Home = () => {
  return (
    <div className="home-container">
      <Card className="shadow-lg p-5 mb-4 home-card">
        <h1 className="home-heading mb-4">Welcome to the DES Encryption/Decryption Tool</h1>
        <p className="lead mb-5">Secure your messages with robust DES encryption and decryption. Easy to use, secure, and fast!</p>
        <div className="d-flex justify-content-center mt-4 flex-wrap gap-4">
          <Link to="/encryption">
            <Button variant="primary" className="btn-lg home-btn">
              <FaKey className="me-2" /> Encrypt
            </Button>
          </Link>
          <Link to="/decryption">
            <Button variant="success" className="btn-lg home-btn">
              <FaLock className="me-2" /> Decrypt
            </Button>
          </Link>
          <Link to="/dashboard">
            <Button variant="info" className="btn-lg home-btn">
              <FaTachometerAlt className="me-2" /> Dashboard
            </Button>
          </Link>
          <Link to="/generate-key">
            <Button variant="secondary" className="btn-lg home-btn">
              <FaKey className="me-2" /> Generate Key
            </Button>
          </Link>
        </div>
      </Card>
    </div>
  );
};

export default Home;
