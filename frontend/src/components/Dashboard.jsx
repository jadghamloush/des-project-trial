import React, { useState, useEffect } from 'react';
import { Card, Spinner } from 'react-bootstrap';
import { LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import './Dashboard.css';

const Dashboard = () => {
  const [metrics, setMetrics] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulating API call for demo
    const fetchMetrics = () => {
      setTimeout(() => {
        setMetrics([
          { operation: 'Encrypt', time: 1.2 },
          { operation: 'Decrypt', time: 0.9 },
          { operation: 'Encrypt', time: 1.5 },
          { operation: 'Decrypt', time: 1.1 },
          { operation: 'Encrypt', time: 1.3 },
          { operation: 'Decrypt', time: 1.0 },
        ]);
        setLoading(false);
      }, 2000);
    };

    fetchMetrics();
  }, []);

  return (
    <Card className="shadow-lg p-4 mb-4 dashboard-card">
      <h2 className="text-center text-primary mb-4">Performance Dashboard</h2>
      {loading ? (
        <div className="text-center py-5">
          <Spinner animation="border" role="status" className="spinner" />
          <div className="mt-2 text-muted">Loading Metrics...</div>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={metrics}>
            <XAxis dataKey="operation" />
            <YAxis />
            <Tooltip />
            <Legend verticalAlign="top" height={36} />
            <Line type="monotone" dataKey="time" stroke="#6a5acd" activeDot={{ r: 8 }} />
          </LineChart>
        </ResponsiveContainer>
      )}
    </Card>
  );
};

export default Dashboard;
