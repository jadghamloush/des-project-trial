// src/components/ErrorBoundary.jsx
import React from 'react';
import { Alert } from 'react-bootstrap';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, errorInfo: '' };
  }

  static getDerivedStateFromError(error) {
    // Update state so next render shows fallback UI
    return { hasError: true, errorInfo: error.toString() };
  }

  componentDidCatch(error, errorInfo) {
    // You can log the error to an error reporting service here
    console.error("Error Boundary Caught an error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return <Alert variant="danger">Something went wrong: {this.state.errorInfo}</Alert>;
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
