const express = require("express");
const cors = require("cors");
const { spawn } = require("child_process");

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());


// --------------------------------------------------
// RUN PYTHON ANALYZER
// --------------------------------------------------

function runML(url) {
  return new Promise((resolve, reject) => {
    const python = spawn("py", ["ml\\predict.py", url], {
      cwd: ".."
    });

    let output = "";
    let errorOutput = "";

    python.stdout.on("data", (data) => {
      output += data.toString();
    });

    python.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    python.on("close", (code) => {
      if (code !== 0) {
        reject(
          new Error(
            errorOutput || "Python analyzer failed"
          )
        );
        return;
      }

      try {
        resolve(JSON.parse(output));
      } catch (error) {
        reject(
          new Error("Could not read Python analysis")
        );
      }
    });
  });
}


// --------------------------------------------------
// HOME ROUTE
// --------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    message: "PhishGuard Backend is running!"
  });
});


// --------------------------------------------------
// URL ANALYSIS
// --------------------------------------------------

app.post("/api/check-url", async (req, res) => {
  const { url } = req.body;

  if (!url || !url.trim()) {
    return res.status(400).json({
      error: "URL is required"
    });
  }

  try {

    const mlResult = await runML(url);

    const warnings = [];

    const lowerURL = url.toLowerCase();


    // --------------------------------------------------
    // HTTPS CHECK
    // --------------------------------------------------

    if (!lowerURL.startsWith("https://")) {
      warnings.push(
        "URL does not use HTTPS"
      );
    }


    // --------------------------------------------------
    // SUSPICIOUS KEYWORDS
    // --------------------------------------------------

    const suspiciousWords = [
      "login",
      "verify",
      "verification",
      "secure",
      "account",
      "update",
      "password",
      "signin",
      "bank"
    ];

    const foundWords = suspiciousWords.filter(
      (word) => lowerURL.includes(word)
    );

    if (foundWords.length > 0) {
      warnings.push(
        `Suspicious keyword(s): ${foundWords.join(", ")}`
      );
    }


    // --------------------------------------------------
    // IP ADDRESS DETECTION
    // --------------------------------------------------

    const ipMatch = url.match(
      /https?:\/\/(\d{1,3}\.){3}\d{1,3}/
    );

    if (ipMatch) {
      warnings.push(
        "URL uses an IP address instead of a domain name"
      );
    }


    // --------------------------------------------------
    // @ SYMBOL DETECTION
    // --------------------------------------------------

    if (url.includes("@")) {
      warnings.push(
        "URL contains an @ symbol, which can hide the real destination"
      );
    }


    // --------------------------------------------------
    // TYPOSQUATTING DETECTION
    // --------------------------------------------------

    const trustedDomains = [
      "google.com",
      "paypal.com",
      "microsoft.com",
      "amazon.com",
      "apple.com",
      "facebook.com",
      "instagram.com",
      "linkedin.com",
      "github.com"
    ];

    const domainMatch = url.match(
      /^https?:\/\/([^/]+)/
    );

    if (domainMatch) {

      const hostname = domainMatch[1]
        .toLowerCase()
        .replace(/^www\./, "");

      for (const trusted of trustedDomains) {

        if (
          hostname !== trusted &&
          (
            hostname.includes(
              trusted.replace(".com", "")
            )
          )
        ) {
          warnings.push(
            `Possible impersonation of trusted domain: ${trusted}`
          );
        }
      }


      // Common look-alike domains

      if (
        hostname.includes("paypa1") ||
        hostname.includes("g00gle") ||
        hostname.includes("micros0ft")
      ) {
        warnings.push(
          "Possible typosquatting or homoglyph attack detected"
        );
      }
    }


    // --------------------------------------------------
    // RESPONSE
    // --------------------------------------------------

    res.json({
      url,
      risk: mlResult.risk,
      score: mlResult.score,
      phishing_probability:
        mlResult.phishing_probability,
      features: mlResult.features,
      warnings
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "URL analysis failed"
    });
  }
});


// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {
  console.log(
    `PhishGuard backend running on http://localhost:${PORT}`
  );
});