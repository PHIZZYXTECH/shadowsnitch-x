import { useState, useEffect } from "react";

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [onionMirror, setOnionMirror] = useState<string | null>(null);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/recent-scans")
      .then(res => res.json())
      .then(data => setHistory(data.reverse()));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setOnionMirror(null);

    try {
      const res = await fetch("http://127.0.0.1:8000/analyze-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      const data = await res.json();
      if (data?.error) setError(data.error);
      else {
        setResult(data);
        setHistory([data, ...history.slice(0, 9)]);
      }
    } catch (err: any) {
      setError(err.message || "Something went wrong");
    }
  };

  const handleDarkwebCrawl = async () => {
    setOnionMirror(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/crawl-darkweb", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      setOnionMirror(data?.onion_mirror || "No onion mirror found");
    } catch (err) {
      setOnionMirror("Error fetching dark web data");
    }
  };

  const scoreColor = (score: number) => {
    if (score <= 1) return "lime";
    if (score <= 3) return "orange";
    return "red";
  };

  return (
    <main style={{
      padding: "2rem",
      fontFamily: "'Courier New', monospace",
      background: "linear-gradient(135deg, #000814, #001d3d)",
      color: "#e3e3e3",
      minHeight: "100vh"
    }}>
      <style>{`
        @keyframes glowPulse {
          0% { text-shadow: 0 0 8px #00ffae, 0 0 20px #00f7ff; }
          50% { text-shadow: 0 0 20px #00f7ff, 0 0 30px #00ffae; }
          100% { text-shadow: 0 0 8px #00ffae, 0 0 20px #00f7ff; }
        }
        @keyframes blink {
          0%, 80%, 100% { opacity: 0; }
          40% { opacity: 1; }
        }
        .snitch-header {
          animation: glowPulse 2s ease-in-out infinite;
          transition: all 0.3s ease-in-out;
        }
        .snitch-header:hover {
          transform: scale(1.05);
          background: linear-gradient(90deg, #ff00c8, #00ffe7);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        .blinking-dots span {
          opacity: 0;
          animation: blink 1.5s infinite;
        }
        .blinking-dots span:nth-child(1) { animation-delay: 0s; }
        .blinking-dots span:nth-child(2) { animation-delay: 0.3s; }
        .blinking-dots span:nth-child(3) { animation-delay: 0.6s; }

        .analyze-button {
          background: linear-gradient(to right, #00ffae, #00f7ff);
          color: #000;
          border: none;
          font-weight: bold;
          box-shadow: 0 0 10px #00ffae;
          transition: all 0.3s ease-in-out;
        }
        .analyze-button:hover {
          background: linear-gradient(to right, #ff00c8, #00ffe7);
          box-shadow: 0 0 20px #ff00c8;
          transform: scale(1.05);
        }
        .darkweb-btn {
          font-family: 'Courier New', monospace;
          margin-top: 0.5rem;
          padding: 0.9rem 2rem;
          border-radius: 8px;
          background: #000;
          color: #ff0040;
          border: 1px solid #ff0040;
          box-shadow: 0 0 10px #ff0040;
          transition: all 0.3s ease-in-out;
          cursor: pointer;
        }
        .darkweb-btn:hover {
          background: linear-gradient(to right, #ff0040, #6000ff);
          color: #00ffae;
          box-shadow: 0 0 25px #ff0040;
          transform: scale(1.05);
        }
      `}</style>

      <h1 className="snitch-header" style={{
        fontSize: "3rem",
        marginBottom: "1rem",
        fontWeight: "bold",
        background: "linear-gradient(90deg, #00ffae, #00f7ff)",
        WebkitBackgroundClip: "text",
        WebkitTextFillColor: "transparent",
        display: "flex",
        alignItems: "center",
        gap: "0.5rem"
      }}>
        💀🕸️ ShadowSnitch X is watching
        <span className="blinking-dots">
          <span>.</span><span>.</span><span>.</span>
        </span>
      </h1>

      <form onSubmit={handleSubmit} style={{ marginBottom: "1.5rem", display: "flex", gap: "1rem", flexWrap: "wrap" }}>
        <input
          type="text"
          placeholder="Paste a suspicious link..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{
            padding: "1rem",
            width: "350px",
            border: "1px solid #333",
            borderRadius: "8px",
            background: "#0e1222",
            color: "#fff",
            fontSize: "1rem"
          }}
        />
        <button type="submit" className="analyze-button" style={{
          padding: "1rem 2rem",
          fontSize: "1rem",
          borderRadius: "8px",
          cursor: "pointer"
        }}>
          ⚡ Analyze
        </button>
      </form>

      <div style={{ marginBottom: "2rem" }}>
        <button className="darkweb-btn" onClick={handleDarkwebCrawl}>
          🕷️ Crawl Dark Web
        </button>
        {onionMirror && (
          <div style={{ marginTop: "1rem", color: "#ff0040" }}>
            🌐 Onion Mirror: {onionMirror}
          </div>
        )}
      </div>

      {error && (
        <div style={{ color: "red", marginBottom: "1rem" }}>
          ❌ {error}
        </div>
      )}

      {result && (
        <div style={{
          background: "#0e1222",
          padding: "1.5rem",
          borderRadius: "10px",
          boxShadow: "0 0 15px #00ffae",
          marginBottom: "2rem"
        }}>
          <h2>📊 Scan Report</h2>
          <p><strong>🔗 Original:</strong> {result.original_url}</p>
          <p><strong>🎯 Final:</strong> {result.final_destination}</p>
          <p><strong>⚠️ Phishing Score:</strong> <span style={{ color: scoreColor(result.phishing_score) }}>{result.phishing_score} / 5</span></p>

          {result.threat_tags?.length > 0 && (
            <div style={{ margin: "1rem 0" }}>
              <strong>🧠 Threat Tags:</strong>{" "}
              {result.threat_tags.map((tag: string, i: number) => (
                <span key={i} style={{
                  background: "#111",
                  color: "lime",
                  borderRadius: "6px",
                  padding: "0.2rem 0.6rem",
                  marginRight: "0.4rem",
                  fontSize: "0.85rem"
                }}>{tag}</span>
              ))}
            </div>
          )}

          <details><summary>🧭 Redirect Chain</summary>
            <ul>{result.redirect_chain.map((link: string, i: number) => <li key={i}>{link}</li>)}</ul>
          </details>

          <details><summary>👮 WHOIS Info</summary>
            <ul>
              {result.domain_info?.error ? <li>{result.domain_info.error}</li> : (
                <>
                  <li>Domain: {result.domain_info.domain}</li>
                  <li>Registrar: {result.domain_info.registrar}</li>
                  <li>Created: {result.domain_info.creation_date}</li>
                  <li>Expires: {result.domain_info.expiration_date}</li>
                  <li>Country: {result.domain_info.country}</li>
                </>
              )}
            </ul>
          </details>

          <details><summary>🌍 Geo + ASN</summary>
            <ul>
              <li>IP: {result.geo_info.ip}</li>
              <li>Location: {result.geo_info.city}, {result.geo_info.country}</li>
              <li>Org: {result.geo_info.org}</li>
              <li>ASN: {result.geo_info.asn}</li>
            </ul>
          </details>

          <details><summary>🧑‍💻 Clone Detection + Blacklist</summary>
            <ul>
              <li>Clone Suspected: {result.is_clone ? "⚠️ Yes" : "✅ No"}</li>
              <li>Blacklist Status: {result.blacklist_status}</li>
            </ul>
          </details>

          <details><summary>📡 Related Domains</summary>
            <ul>{result.related_domains.map((d: string, i: number) => <li key={i}>{d}</li>)}</ul>
          </details>

          <details><summary>🧠 Metadata</summary>
            <p>Title: {result.page_metadata?.title}</p>
            <ul>
              {result.page_metadata?.meta && Object.entries(result.page_metadata.meta).map(([k, v], i) => (
                <li key={i}><strong>{k}</strong>: {v}</li>
              ))}
            </ul>
          </details>

          <p style={{ marginTop: "1rem", fontSize: "0.8rem", color: "#aaa" }}>
            🕓 Scanned: {new Date(result.timestamp).toLocaleString()}
          </p>
        </div>
      )}

      {history.length > 0 && (
        <div>
          <h2 style={{ marginBottom: "1rem", fontSize: "1.5rem", color: "#00ffae" }}>
            🗂️ Recent Investigations
          </h2>
          {history.map((scan, index) => (
            <div key={index} style={{
              border: "1px solid #222",
              padding: "1rem",
              borderRadius: "8px",
              marginBottom: "1rem",
              background: "#0e1222"
            }}>
              <p><strong>🔗 {scan.original_url}</strong></p>
              <p>🎯 {scan.final_destination}</p>
              <p>⚠️ Score: <span style={{ color: scoreColor(scan.phishing_score) }}>{scan.phishing_score}</span></p>
              <div style={{ fontSize: "0.8rem", color: "#aaa" }}>🕓 {new Date(scan.timestamp).toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
