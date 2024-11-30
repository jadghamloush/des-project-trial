// frontend/src/App.js

import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import CustomNavbar from './components/CustomNavbar';
import Home from './components/Home';
import EncryptionForm from './components/EncryptionForm';
import DecryptionForm from './components/DecryptionForm';
import Dashboard from './components/Dashboard';
import KeyGeneration from './components/KeyGeneration';
import ErrorBoundary from './components/ErrorBoundary';
import ThemeProvider from './context/ThemeContext';
import DESInfoPage from './components/DESInfoPage';
import Chatbot from './components/chatbot'; 
import DESQuizPage from "./components/DESQuizPage";
import HistoryView from "./components/HistoryView"; // Import HistoryView

import './App.css';

function App() {
  useEffect(() => {
    const savedTheme = localStorage.getItem("theme") || "light";
    document.documentElement.setAttribute("data-theme", savedTheme);
  }, []);

  return (
    <ThemeProvider>
      <Router>
        <CustomNavbar />
        <div className="container mt-5 pt-4">
          <ErrorBoundary>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/encryption" element={<EncryptionForm />} />
              <Route path="/decryption" element={<DecryptionForm />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/generate-key" element={<KeyGeneration />} />
              <Route path="/des-info" element={<DESInfoPage />} />
              <Route path="/des-quiz" element={<DESQuizPage />} />
              <Route path="/history" element={<HistoryView />} /> {/* Add History Route */}
              {/* Add other routes as needed */}
            </Routes>
          </ErrorBoundary>
        </div>
        <Chatbot /> {/* Add the chatbot here */}
      </Router>
    </ThemeProvider>
  );
}

export default App;
