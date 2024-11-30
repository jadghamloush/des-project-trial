// frontend/src/components/CustomNavbar.jsx

import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { FaHome, FaKey, FaLock, FaTachometerAlt, FaBars, FaTimes, FaHistory, FaInfoCircle } from 'react-icons/fa';  // Added FaHistory
import ThemeToggle from './ThemeToggle';
import './CustomNavbar.css';

const CustomNavbar = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);

  const toggleMenuOpen = () => {
    setIsMenuOpen(!isMenuOpen);
  };

  // Close menu on navigation
  const handleNavLinkClick = () => {
    if (isMenuOpen) setIsMenuOpen(false);
  };

  // Handle scroll to add shadow
  useEffect(() => {
    const handleScroll = () => {
      const offset = window.scrollY;
      if (offset > 50) {
        setIsScrolled(true);
      } else {
        setIsScrolled(false);
      }
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <>
      <div className={`navbar-overlay ${isMenuOpen ? 'open' : ''}`} onClick={toggleMenuOpen}></div>
      <nav className={`navbar-custom ${isScrolled ? 'scrolled' : ''}`}>
        <div className="navbar-left">
          <button className="navbar-burger" onClick={toggleMenuOpen} aria-label="Toggle Menu">
            {isMenuOpen ? <FaTimes /> : <FaBars />}
          </button>
          <NavLink to="/" className="navbar-title" onClick={handleNavLinkClick}>
            <FaHome className="me-2" /> DES Tool
          </NavLink>
        </div>
        <div className={`navbar-menu ${isMenuOpen ? 'open' : ''}`}>
          <NavLink to="/encryption" className="nav-link" onClick={handleNavLinkClick}>
            <FaKey className="me-1" /> Encryption
          </NavLink>
          <NavLink to="/decryption" className="nav-link" onClick={handleNavLinkClick}>
            <FaLock className="me-1" /> Decryption
          </NavLink>
          <NavLink to="/dashboard" className="nav-link" onClick={handleNavLinkClick}>
            <FaTachometerAlt className="me-1" /> Dashboard
          </NavLink>
          <NavLink to="/generate-key" className="nav-link" onClick={handleNavLinkClick}>
            <FaKey className="me-1" /> Generate Key
          </NavLink>
          <NavLink to="/des-info" className="nav-link" onClick={handleNavLinkClick}> 
            <FaInfoCircle className="me-1" /> DES Info
          </NavLink>
          <NavLink to="/des-quiz" className="nav-link" onClick={handleNavLinkClick}>
            <FaInfoCircle className='me-1' /> DES Quiz
          </NavLink>
          <NavLink to="/history" className="nav-link" onClick={handleNavLinkClick}> {/* Add History Link */}
            <FaHistory className="me-1" /> History
          </NavLink>
        </div>
        <div className="navbar-right">
          <ThemeToggle />
        </div>
      </nav>
    </>
  );
};

export default CustomNavbar;
