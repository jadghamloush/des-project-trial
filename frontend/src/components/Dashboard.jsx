import React, { useState, useEffect } from 'react';
import { Card, Spinner } from 'react-bootstrap';
import { LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import './Dashboard.css';

const Dashboard = () => {
  const [metrics, setMetrics] = useState([]);
  const [loading, setLoading] = useState(true);
  const [last_updated, setLastUpdated] = useState(null); // New state for last updated

  useEffect(() => {
    // Simulating API call for demo
    const fetchMetrics = async  () => {
      try{
        setLoading(true);
        const response = await fetch('http://127.0.0.1:5000/dashboard');
        const data = await response.json();

        if (data.success) {
          setMetrics(data.data); // Replace metrics with the ordered data
          setLastUpdated(data.last_updated);
        } else {
          console.error('Failed to fetch metrics:', data);
        }

      } catch (error) {
        console.error('Error fetching metrics:', error);
      } finally {
        setLoading(false);
      }
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
        <>
          <ResponsiveContainer width="100%" height={400}>
            <LineChart data={metrics}>
              <XAxis dataKey="operation" />
              <YAxis />
              <Tooltip />
              <Legend verticalAlign="top" height={36} />
              <Line type="monotone" dataKey="time" stroke="#6a5acd" activeDot={{ r: 8 }} />
            </LineChart>
          </ResponsiveContainer>
          <div className="text-center mt-4">
            <p className="text-muted">Last Updated: {last_updated || 'Fetching...'}</p>
          </div>
        </>
      )}
    </Card>
  );
};

export default Dashboard;
