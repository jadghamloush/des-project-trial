import React from 'react';
import ReactDOM from 'react-dom/client';  // Updated import for React 18
import App from './App';
import ThemeProvider from './context/ThemeContext';
import './index.css';

const root = ReactDOM.createRoot(document.getElementById('root'));

root.render(
  <React.StrictMode>
    <ThemeProvider>
      <App />
    </ThemeProvider>
  </React.StrictMode>
);
