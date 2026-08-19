import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const checkUrl = async () => {
    if (!url.trim()) {
      setResult({
        type: "warning",
        message: "Please enter a URL to check.",
        warnings: []
      });
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(
        "http://localhost:5000/api/check-url",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Something went wrong"
        );
      }

      const scanResult = {
        type:
          data.risk === "HIGH"
            ? "danger"
            : data.risk === "MEDIUM"
              ? "warning"
              : "safe",

        message: `${data.risk} RISK — Score: ${data.score}/100`,

        score: data.score,

        risk: data.risk,

        warnings: data.warnings || []
      };

      setResult(scanResult);

      const newHistoryItem = {
        url,
        risk: data.risk,
        score: data.score
      };

      setHistory((previousHistory) => [
        newHistoryItem,
        ...previousHistory
      ].slice(0, 10));

    } catch (error) {
      setResult({
        type: "danger",
        message: "Backend is not reachable.",
        warnings: []
      });
    } finally {
      setLoading(false);
    }
  };

  const clearScan = () => {
    setUrl("");
    setResult(null);
  };

  const clearHistory = () => {
    setHistory([]);
  };

  const scanFromHistory = (historyUrl) => {
    setUrl(historyUrl);
  };

  const totalScans = history.length;

  const safeScans = history.filter(
    (item) => item.risk === "LOW"
  ).length;

  const threatScans = history.filter(
    (item) =>
      item.risk === "MEDIUM" ||
      item.risk === "HIGH"
  ).length;

  return (
    <div className="app">

      <header className="navbar">

        <div className="logo">
          🛡️ PhishGuard
        </div>

        <span className="tagline">
          AI-Powered Phishing Detection
        </span>

      </header>


      <main className="hero">

        <div className="hero-content">

          <h1>
            Detect Phishing.
            <br />
            <span>Stay Protected.</span>
          </h1>

          <p>
            Analyze suspicious URLs and identify
            potential phishing threats before they
            put your information at risk.
          </p>


          <div className="scanner">

            <input
              type="text"
              placeholder="Enter a suspicious URL..."
              value={url}
              onChange={(e) =>
                setUrl(e.target.value)
              }
              disabled={loading}
            />

            <button
              onClick={checkUrl}
              disabled={loading}
            >
              {loading
                ? "🔄 Analyzing..."
                : "🔍 Check URL"}
            </button>

            <button
              className="clear-button"
              onClick={clearScan}
              disabled={loading}
            >
              Clear
            </button>

          </div>


          {result && (

            <div
              className={`result ${result.type}`}
            >

              <h3>
                {result.message}
              </h3>


              {result.score !== undefined && (

                <div className="risk-meter">

                  <div className="meter-track">

                    <div
                      className="meter-fill"
                      style={{
                        width:
                          `${result.score}%`
                      }}
                    ></div>

                  </div>


                  <div className="meter-labels">

                    <span>
                      Safe
                    </span>

                    <span>
                      Risk
                    </span>

                  </div>

                </div>

              )}


              {result.warnings &&
                result.warnings.length > 0 && (

                  <ul>

                    {result.warnings.map(
                      (warning, index) => (

                        <li key={index}>
                          {warning}
                        </li>

                      )
                    )}

                  </ul>

                )}

            </div>

          )}

        </div>

      </main>


      {history.length > 0 && (

        <section className="dashboard">

          <div className="stats-grid">

            <div className="stat-card">

              <span className="stat-icon">
                🔎
              </span>

              <div>

                <strong>
                  {totalScans}
                </strong>

                <p>
                  Total Scans
                </p>

              </div>

            </div>


            <div className="stat-card safe-stat">

              <span className="stat-icon">
                🟢
              </span>

              <div>

                <strong>
                  {safeScans}
                </strong>

                <p>
                  Safe
                </p>

              </div>

            </div>


            <div className="stat-card threat-stat">

              <span className="stat-icon">
                🚨
              </span>

              <div>

                <strong>
                  {threatScans}
                </strong>

                <p>
                  Threats
                </p>

              </div>

            </div>

          </div>


          <div className="history-section">

            <div className="history-header">

              <h2>
                📋 Scan History
              </h2>

              <button
                className="clear-history"
                onClick={clearHistory}
              >
                Clear History
              </button>

            </div>


            <div className="history-list">

              {history.map(
                (item, index) => (

                  <div
                    className="history-item"
                    key={index}
                    onClick={() =>
                      scanFromHistory(
                        item.url
                      )
                    }
                  >

                    <div className="history-url">

                      <span
                        className={`history-indicator ${item.risk.toLowerCase()}`}
                      >
                      </span>

                      <span>
                        {item.url}
                      </span>

                    </div>


                    <div className="history-risk">

                      <strong>
                        {item.risk}
                      </strong>

                      <span>
                        {item.score}/100
                      </span>

                    </div>

                  </div>

                )
              )}

            </div>

          </div>

        </section>

      )}


      <section className="features">

        <div className="feature-card">

          <div className="icon">
            🔗
          </div>

          <h3>
            URL Analysis
          </h3>

          <p>
            Examines suspicious URL characteristics
            and patterns.
          </p>

        </div>


        <div className="feature-card">

          <div className="icon">
            🤖
          </div>

          <h3>
            ML Detection
          </h3>

          <p>
            Uses intelligent classification to identify
            potentially harmful URLs.
          </p>

        </div>


        <div className="feature-card">

          <div className="icon">
            🛡️
          </div>

          <h3>
            Threat Protection
          </h3>

          <p>
            Helps users identify phishing threats
            before interacting with them.
          </p>

        </div>

      </section>

    </div>
  );
}

export default App;