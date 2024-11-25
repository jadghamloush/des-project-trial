import React, { useContext } from 'react';
import { Button } from 'react-bootstrap';
import { FaSun, FaMoon } from 'react-icons/fa';
import { ThemeContext } from '../context/ThemeContext';
import './ThemeToggle.css';

const ThemeToggle = () => {
  const { theme, toggleTheme } = useContext(ThemeContext);

  return (
    <Button 
      variant="outline-light" 
      onClick={toggleTheme} 
      className="theme-toggle-btn"
    >
      {theme === 'light' ? <FaMoon className="theme-icon" /> : <FaSun className="theme-icon" />}
      <span className="ms-2 theme-text">
        {theme === 'light' ? 'Dark' : 'Light'} Mode
      </span>
    </Button>
  );
};

export default ThemeToggle;
