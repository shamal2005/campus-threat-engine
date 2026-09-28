import React, { useState } from 'react';

// Backend API Base URL
const API_BASE_URL = 'http://127.0.0.1:8000';

function App() {
  // State for flow results, loading status, error message, and copy feedback
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copiedIp, setCopiedIp] = useState(null);

  // Step 2: Handle "Scan Network Traffic" button click
  const handleScanTraffic = async () => {
    setLoading(true);
    setError(null);

    try {
      // 1. Fetch sample flows from backend GET /sample
      const sampleResponse = await fetch(`${API_BASE_URL}/sample`);
      if (!sampleResponse.ok) {
        throw new Error(`Failed to load network samples (${sampleResponse.status})`);
      }
      const sampleData = await sampleResponse.json();

      // 2. Send sampled flows to backend POST /predict
      const predictResponse = await fetch(`${API_BASE_URL}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sampleData),
      });

      if (!predictResponse.ok) {
        throw new Error(`Prediction request failed (${predictResponse.status})`);
      }

      const predictionResults = await predictResponse.json();
      setFlows(predictionResults);
    } catch (err) {
      console.error(err);
      setError(err.message || 'Error communicating with backend server.');
    } finally {
      setLoading(false);
    }
  };

  // Helper: Copy Cisco ACL command to clipboard
  const handleCopyAcl = (ip, aclText) => {
    navigator.clipboard.writeText(aclText);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // Filter unique attacks to show alert and ACL box once per attacker IP
  const attackFlows = flows.filter((f) => f.prediction === 'PortScan');
  const uniqueAttackerIps = [...new Set(attackFlows.map((f) => f.source_ip))];

  // Group unique Cisco ACL commands (one per attacker IP)
  const uniqueAcls = [];
  uniqueAttackerIps.forEach((ip) => {
    const matchingFlow = attackFlows.find((f) => f.source_ip === ip && f.cisco_acl);
    if (matchingFlow) {
      uniqueAcls.push({
        ip,
        severity: matchingFlow.severity,
        cisco_acl: matchingFlow.cisco_acl,
      });
    }
  });

  return (
    <div className="container">
      {/* 1. Header with Title and Scan Button */}
      <header className="header">
        <div>
          <h1>AI-Assisted Campus Threat Detection</h1>
          <p className="demo-note">Demo mode: replaying recorded CICIDS2017 traffic. IP addresses are simulated.</p>
        </div>
        <button
          className="btn-scan"
          onClick={handleScanTraffic}
          disabled={loading}
        >
          {loading ? (
            <>
              <span className="spinner"></span> Replaying...
            </>
          ) : (
            'Replay Sample Traffic'
          )}
        </button>
      </header>

      {/* Error Banner if API call fails */}
      {error && (
        <div className="error-banner">
          ⚠️ <strong>Connection Error:</strong> {error}. Ensure FastAPI is running at {API_BASE_URL}.
        </div>
      )}

      {/* 3. Red Alert Banner if any attack is detected */}
      {attackFlows.length > 0 && (
        <div className="alert-banner">
          <div className="alert-icon">🚨</div>
          <div className="alert-content">
            <h3>Threat Detected on Campus Network!</h3>
            {uniqueAttackerIps.map((ip) => {
              const highestSeverity = attackFlows.find((f) => f.source_ip === ip)?.severity || 'High';
              return (
                <p key={ip}>
                  <strong>PortScan detected from {ip}</strong>
                  <span className={`badge-severity badge-${highestSeverity.toLowerCase()}`}>
                    {highestSeverity} Severity
                  </span>
                </p>
              );
            })}
          </div>
        </div>
      )}

      {/* 5. Cisco ACL Box for Attacker IP (shown once per attacker IP) */}
      {uniqueAcls.length > 0 &&
        uniqueAcls.map(({ ip, severity, cisco_acl }) => (
          <div key={ip} className="acl-card">
            <div className="acl-header">
              <div className="acl-header-left">
                <span className="acl-title">Switch Mitigation ACL</span>
                <span className="acl-ip-tag">{ip}</span>
                <span className={`badge-severity badge-${severity.toLowerCase()}`}>
                  {severity}
                </span>
              </div>
              <button
                className={`btn-copy ${copiedIp === ip ? 'copied' : ''}`}
                onClick={() => handleCopyAcl(ip, cisco_acl)}
              >
                {copiedIp === ip ? '✓ Copied!' : 'Copy Command'}
              </button>
            </div>
            <pre className="acl-code">{cisco_acl}</pre>
            <div className="acl-note">Paste this on the Core Router CLI to block the attacker.</div>
          </div>
        ))}

      {/* 4. Table of all flows (Attack rows in red, Normal rows in green) */}
      <div className="table-card">
        <div className="table-header-bar">
          <h2>Network Flow Telemetry</h2>
          {flows.length > 0 && (
            <span className="table-summary">
              {flows.length} flows analyzed ({attackFlows.length} threats, {flows.length - attackFlows.length} benign)
            </span>
          )}
        </div>

        {flows.length === 0 ? (
          <div className="state-box">
            <div className="state-icon">📡</div>
            <p>No traffic analyzed yet.</p>
            <p style={{ marginTop: '6px', color: '#64748b' }}>
              Click <strong>"Replay Sample Traffic"</strong> above to capture and evaluate flows.
            </p>
          </div>
        ) : (
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((flow, index) => {
                  const isAttack = flow.prediction === 'PortScan';
                  return (
                    <tr
                      key={index}
                      className={isAttack ? 'row-attack' : 'row-normal'}
                    >
                      <td className="ip-text">{flow.source_ip}</td>
                      <td>
                        <span className={`pill ${isAttack ? 'pill-attack' : 'pill-normal'}`}>
                          {flow.prediction}
                        </span>
                      </td>
                      <td>{(flow.confidence * 100).toFixed(1)}%</td>
                      <td>
                        <span
                          className={`badge-severity badge-${flow.severity.toLowerCase()}`}
                        >
                          {flow.severity}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
