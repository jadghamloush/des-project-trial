import React, { createContext, useState, useEffect, useCallback } from 'react';

export const ThemeContext = createContext();

const ThemeProvider = ({ children }) => {
  // Retrieve the theme from localStorage, default to 'light' if not found
  const storedTheme = localStorage.getItem('theme') || 'light';
  const [theme, setTheme] = useState(storedTheme);

  useEffect(() => {
    // Set the theme attribute on the <html> element for global styling
    document.documentElement.setAttribute('data-theme', theme);
    // Store the theme in localStorage for persistence
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    // Toggle theme between light and dark
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

export default ThemeProvider;
