import { useEffect, useState } from "react";
import "./App.css";

const HISTORY_KEY = "phishguard_scan_history";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [scanHistory, setScanHistory] = useState(() => {
    try {
      const saved = localStorage.getItem(HISTORY_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    localStorage.setItem(
      HISTORY_KEY,
      JSON.stringify(scanHistory)
    );
  }, [scanHistory]);

  const getRiskClass = (risk) => {
    const value = String(risk || "").toUpperCase();

    if (value.includes("HIGH")) return "high-risk";
    if (value.includes("MEDIUM")) return "medium-risk";
    return "low-risk";
  };

  const getRiskIcon = (risk) => {
    const value = String(risk || "").toUpperCase();

    if (value.includes("HIGH")) return "🔴";
    if (value.includes("MEDIUM")) return "🟠";
    return "🟢";
  };

  const getRiskLabel = (risk) => {
    const value = String(risk || "").toUpperCase();

    if (value.includes("HIGH")) return "HIGH RISK";
    if (value.includes("MEDIUM")) return "MEDIUM RISK";
    return "LOW RISK";
  };

  const checkUrl = async () => {
    if (!url.trim()) {
      setError("Please enter a URL.");
      setResult(null);
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(
        "http://localhost:5000/api/check-url",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            url: url.trim(),
          }),
        }
      );

      const data = await response.json();

      if (!response.ok || data.error) {
        throw new Error(
          data.error || "URL analysis failed"
        );
      }

      setResult(data);

      const historyItem = {
        id: Date.now(),

        url: data.url || url.trim(),

        final_resolved_url:
          data.final_resolved_url || "",

        risk: data.risk || "LOW RISK",

        score: Number(data.score) || 0,

        phishing_probability:
          data.phishing_probability !== undefined &&
          data.phishing_probability !== null
            ? Number(data.phishing_probability)
            : null,

        warnings: Array.isArray(data.warnings)
          ? data.warnings
          : [],

        security_checks:
          data.security_checks || {},

        brand_impersonation:
          data.brand_impersonation || null,

        legitimate_domain:
          data.legitimate_domain || false,

        official_brand:
          data.official_brand || null,

        official_domain:
          data.official_domain || null,

        timestamp:
          new Date().toLocaleString(),
      };

      setScanHistory((previous) => [
        historyItem,
        ...previous,
      ]);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Backend unreachable. Make sure the backend is running."
      );
    } finally {
      setLoading(false);
    }
  };

  const clearResult = () => {
    setUrl("");
    setResult(null);
    setError("");
  };

  const clearHistory = () => {
    if (
      window.confirm(
        "Are you sure you want to clear all scan history?"
      )
    ) {
      setScanHistory([]);
    }
  };

  const deleteHistoryItem = (id) => {
    setScanHistory((previous) =>
      previous.filter((item) => item.id !== id)
    );
  };

  const viewHistoryItem = (item) => {
    setUrl(item.url);

    setResult({
      url: item.url,

      final_resolved_url:
        item.final_resolved_url,

      risk: item.risk,

      score: item.score,

      phishing_probability:
        item.phishing_probability,

      warnings: item.warnings,

      security_checks:
        item.security_checks,

      brand_impersonation:
        item.brand_impersonation,

      legitimate_domain:
        item.legitimate_domain,

      official_brand:
        item.official_brand,

      official_domain:
        item.official_domain,
    });

    setError("");

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const useDemoUrl = (demoUrl) => {
    setUrl(demoUrl);
    setResult(null);
    setError("");
  };

  const score = Math.min(
    100,
    Math.max(0, Number(result?.score) || 0)
  );

  return (
    <div className="app">

      {/* HEADER */}
      <header className="header">
        <div className="logo">🛡️</div>

        <div>
          <h1>PhishGuard-AI</h1>
          <p>
            AI-Powered Phishing URL Detection
          </p>
        </div>
      </header>

      <main className="main">

        {/* INTRO */}
        <section className="intro">
          <h2>Check if a URL is safe</h2>

          <p>
            Enter a website URL and PhishGuard-AI
            will analyze it using machine learning,
            security heuristics and phishing indicators.
          </p>
        </section>

        {/* SEARCH */}
        <div className="search-box">
          <input
            type="text"
            value={url}
            disabled={loading}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                checkUrl();
              }
            }}
            placeholder="Enter URL, e.g. https://google.com"
          />

          <button
            className="check-button"
            onClick={checkUrl}
            disabled={loading}
          >
            {loading ? "Checking..." : "🔍 Check URL"}
          </button>

          <button
            className="clear-button"
            onClick={clearResult}
            disabled={loading}
          >
            Clear
          </button>
        </div>

        {/* ERROR */}
        {error && (
          <div className="error-box">
            ⚠️ {error}
          </div>
        )}

        {/* LOADING */}
        {loading && (
          <div className="loading-box">
            <div className="spinner"></div>

            <p>Analyzing URL...</p>

            <span>
              Checking ML prediction, HTTPS,
              redirects and suspicious patterns.
            </span>
          </div>
        )}

        {/* RESULT */}
        {result && !loading && (
          <div
            className={`result-card ${getRiskClass(
              result.risk
            )}`}
          >

            <div className="result-header">
              <h2>
                {getRiskIcon(result.risk)}{" "}
                {getRiskLabel(result.risk)}
              </h2>

              <div className="score">
                Score: {score}/100
              </div>
            </div>

            {/* RISK BAR */}
            <div className="risk-bar">
              <div
                className="risk-fill"
                style={{
                  width: `${score}%`,
                }}
              ></div>
            </div>

            <div className="risk-labels">
              <span>Safe</span>
              <span>Risk</span>
            </div>

            {/* ANALYZED URL */}
            <div className="url-info">
              <div className="info-title">
                Analyzed URL
              </div>

              <div className="url-value">
                {result.url}
              </div>
            </div>

            {/* FINAL DESTINATION */}
            {result.final_resolved_url &&
              result.final_resolved_url !==
                result.url && (
                <div className="url-info">
                  <div className="info-title">
                    Final Destination
                  </div>

                  <div className="url-value">
                    {result.final_resolved_url}
                  </div>
                </div>
              )}

            {/* ML PROBABILITY */}
            {result.phishing_probability !==
              undefined &&
              result.phishing_probability !== null && (
                <div className="probability-box">
                  <span>
                    ML Phishing Probability
                  </span>

                  <strong>
                    {Number(
                      result.phishing_probability
                    ).toFixed(1)}
                    %
                  </strong>
                </div>
              )}

            {/* SECURITY CHECKS */}
            {result.security_checks && (
              <div className="checks-section">
                <h3>Security Checks</h3>

                <div className="checks-grid">

                  <div className="check-item">
                    <span>HTTPS</span>
                    <strong>
                      {result.security_checks.https
                        ? "✓ Secure"
                        : "✗ Not Secure"}
                    </strong>
                  </div>

                  <div className="check-item">
                    <span>Redirect</span>
                    <strong>
                      {result.security_checks
                        .redirect_detected
                        ? "⚠ Detected"
                        : "✓ None"}
                    </strong>
                  </div>

                  <div className="check-item">
                    <span>IP Address</span>
                    <strong>
                      {result.security_checks
                        .ip_address_detected
                        ? "⚠ Detected"
                        : "✓ None"}
                    </strong>
                  </div>

                  <div className="check-item">
                    <span>@ Symbol</span>
                    <strong>
                      {result.security_checks
                        .at_symbol_detected
                        ? "⚠ Detected"
                        : "✓ None"}
                    </strong>
                  </div>

                  <div className="check-item">
                    <span>Typosquatting</span>
                    <strong>
                      {result.security_checks
                        .typosquatting_detected
                        ? "⚠ Detected"
                        : "✓ None"}
                    </strong>
                  </div>

                  <div className="check-item">
                    <span>Brand Impersonation</span>
                    <strong>
                      {result.security_checks
                        .brand_impersonation_detected
                        ? "⚠ Detected"
                        : "✓ None"}
                    </strong>
                  </div>

                </div>
              </div>
            )}

            {/* BRAND INFO */}
            {result.brand_impersonation && (
              <div className="brand-warning">
                <strong>⚠️ Brand Impersonation</strong>

                <p>
                  Possible{" "}
                  {result.brand_impersonation.attack_type ||
                    "brand"}{" "}
                  impersonating{" "}
                  {result.brand_impersonation.brand ||
                    "a trusted brand"}.
                </p>
              </div>
            )}

            {/* OFFICIAL DOMAIN */}
            {result.legitimate_domain &&
              result.official_brand && (
                <div className="official-message">
                  ✓ Known legitimate domain:{" "}
                  {result.official_brand}
                </div>
              )}

            {/* WARNINGS */}
            {result.warnings &&
              result.warnings.length > 0 && (
                <div className="warnings-section">
                  <h3>⚠️ Security Warnings</h3>

                  <ul>
                    {result.warnings.map(
                      (warning, index) => (
                        <li key={index}>
                          {warning}
                        </li>
                      )
                    )}
                  </ul>
                </div>
              )}

            {/* SAFE */}
            {(!result.warnings ||
              result.warnings.length === 0) &&
              !result.brand_impersonation && (
                <div className="safe-message">
                  ✓ No suspicious security
                  indicators were detected.
                </div>
              )}

          </div>
        )}

        {/* DEMO */}
        <section className="demo-section">
          <h3>Try these examples</h3>

          <div className="demo-buttons">

            <button
              onClick={() =>
                useDemoUrl(
                  "https://google.com"
                )
              }
            >
              🟢 Safe
            </button>

            <button
              onClick={() =>
                useDemoUrl(
                  "https://g00gle.com"
                )
              }
            >
              🔴 Typosquatting
            </button>

            <button
              onClick={() =>
                useDemoUrl(
                  "https://example.com/login/verify"
                )
              }
            >
              🟠 Suspicious
            </button>

            <button
              onClick={() =>
                useDemoUrl(
                  "https://nayan@.com"
                )
              }
            >
              🔴 @ Symbol
            </button>

          </div>
        </section>

        {/* HISTORY */}
        <section className="history-section">

          <div className="history-header">

            <div>
              <h2>🕘 Scan History</h2>

              <p>
                Previous URLs scanned by
                PhishGuard-AI
              </p>
            </div>

            {scanHistory.length > 0 && (
              <button
                className="clear-history-button"
                onClick={clearHistory}
              >
                🗑️ Clear History
              </button>
            )}

          </div>

          {scanHistory.length === 0 ? (
            <div className="empty-history">
              <div className="empty-history-icon">
                🕘
              </div>

              <h3>No scans yet</h3>

              <p>
                Your scanned URLs will appear here.
              </p>
            </div>
          ) : (
            <div className="history-list">

              {scanHistory.map((item) => (
                <div
                  className={`history-item ${getRiskClass(
                    item.risk
                  )}`}
                  key={item.id}
                >

                  <div className="history-main">

                    <div className="history-risk">
                      <span>
                        {getRiskIcon(item.risk)}
                      </span>

                      <strong>
                        {getRiskLabel(item.risk)}
                      </strong>
                    </div>

                    <div className="history-url">
                      {item.url}
                    </div>

                    <div className="history-meta">
                      <span>
                        Score: {item.score}/100
                      </span>

                      {item.phishing_probability !==
                        null && (
                        <span>
                          ML:{" "}
                          {Number(
                            item.phishing_probability
                          ).toFixed(1)}
                          %
                        </span>
                      )}

                      <span>
                        {item.timestamp}
                      </span>
                    </div>

                  </div>

                  <div className="history-actions">

                    <button
                      className="view-button"
                      onClick={() =>
                        viewHistoryItem(item)
                      }
                    >
                      View
                    </button>

                    <button
                      className="delete-button"
                      onClick={() =>
                        deleteHistoryItem(item.id)
                      }
                    >
                      ✕
                    </button>

                  </div>

                </div>
              ))}

            </div>
          )}

        </section>

      </main>

      <footer>
        <p>
          PhishGuard-AI • AI-powered phishing detection
        </p>
      </footer>

    </div>
  );
}

export default App;