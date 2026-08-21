// ============================================================
// PHISHGUARD-AI BACKEND SERVER
// URL + ML + HEURISTICS + BRAND IMPERSONATION
// ============================================================

const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const path = require("path");

// ============================================================
// CREATE EXPRESS APP
// ============================================================

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json({ limit: "10mb" }));


// ============================================================
// MACHINE LEARNING FUNCTION
// ============================================================

function runML(url) {
  return new Promise((resolve, reject) => {

    const pythonScript = path.join(
      __dirname,
      "..",
      "ml",
      "predict.py"
    );

    execFile(
      "python",
      [pythonScript, url],
      {
        timeout: 15000,
        maxBuffer: 1024 * 1024 * 5
      },
      (error, stdout, stderr) => {

        if (error) {

          console.error(
            "ML Error:",
            error.message
          );

          if (stderr) {
            console.error(
              "ML stderr:",
              stderr
            );
          }

          return reject(error);
        }

        try {

          const output =
            stdout.trim();

          console.log(
            "ML Output:",
            output
          );

          const result =
            JSON.parse(output);

          if (result.error) {
            return reject(
              new Error(result.error)
            );
          }

          resolve(result);

        } catch (parseError) {

          console.error(
            "ML JSON Parse Error:",
            parseError.message
          );

          console.error(
            "Raw ML output:",
            stdout
          );

          reject(parseError);
        }
      }
    );
  });
}


// ============================================================
// BASIC TEST ROUTE
// ============================================================

app.get("/", (req, res) => {

  res.json({
    message:
      "PhishGuard-AI backend is running",
    status: "OK"
  });

});


// ============================================================
// HELPER: GET REGISTERED DOMAIN
// ============================================================

function getRegisteredDomain(hostname) {

  if (!hostname) {
    return "";
  }

  const parts =
    hostname
      .toLowerCase()
      .replace(/^www\./, "")
      .split(".");

  if (parts.length < 2) {
    return hostname.toLowerCase();
  }

  const commonSecondLevel = [
    "co.in",
    "com.au",
    "co.uk",
    "co.jp",
    "co.nz",
    "com.br",
    "com.cn",
    "com.sg",
    "com.my",
    "co.za"
  ];

  const lastTwo =
    parts.slice(-2).join(".");

  if (
    commonSecondLevel.includes(
      lastTwo
    ) &&
    parts.length >= 3
  ) {

    return parts
      .slice(-3)
      .join(".");
  }

  return parts
    .slice(-2)
    .join(".");
}


// ============================================================
// HELPER: CHECK SAFE REDIRECT
// ============================================================

function isSafeRedirect(
  originalUrl,
  finalUrl
) {

  try {

    const original =
      new URL(originalUrl);

    const final =
      new URL(finalUrl);

    const originalDomain =
      getRegisteredDomain(
        original.hostname
      );

    const finalDomain =
      getRegisteredDomain(
        final.hostname
      );

    // Same registered domain
    if (
      originalDomain &&
      finalDomain &&
      originalDomain === finalDomain
    ) {
      return true;
    }

    return false;

  } catch (error) {

    return false;
  }
}


// ============================================================
// URL ANALYSIS
// ============================================================

app.post(
  "/api/check-url",
  async (req, res) => {

    let { url } =
      req.body;


    // --------------------------------------------------------
    // VALIDATE INPUT
    // --------------------------------------------------------

    if (
      !url ||
      !url.trim()
    ) {

      return res.status(400).json({
        error:
          "URL is required"
      });

    }


    url =
      url.trim();


    // --------------------------------------------------------
    // ADD PROTOCOL
    // --------------------------------------------------------

    if (
      !url
        .toLowerCase()
        .startsWith("http://") &&
      !url
        .toLowerCase()
        .startsWith("https://")
    ) {

      url =
        "http://" + url;

    }


    try {

      // ======================================================
      // 1. RUN MACHINE LEARNING
      // ======================================================

      const mlResult =
        await runML(url);


      const warnings = [];


      // ======================================================
      // 2. LIVE REDIRECT / HTTPS CHECK
      // ======================================================

      let finalUrl =
        url;

      let isSecure =
        url
          .toLowerCase()
          .startsWith("https://");

      let redirectDetected =
        false;

      let safeRedirect =
        false;


      try {

        const controller =
          new AbortController();

        const timeoutId =
          setTimeout(
            () => {
              controller.abort();
            },
            5000
          );


        const response =
          await fetch(
            url,
            {
              method: "GET",

              redirect: "follow",

              signal:
                controller.signal,

              headers: {
                "User-Agent":
                  "PhishGuard-AI-Security-Scanner/1.0"
              }
            }
          );


        clearTimeout(
          timeoutId
        );


        finalUrl =
          response.url;


        redirectDetected =
          finalUrl.toLowerCase() !==
          url.toLowerCase();


        isSecure =
          finalUrl
            .toLowerCase()
            .startsWith("https://");


        // Check whether redirect stays
        // within the same registered domain

        if (
          redirectDetected
        ) {

          safeRedirect =
            isSafeRedirect(
              url,
              finalUrl
            );

        }

      } catch (fetchError) {

        console.log(
          "Live URL check failed:",
          fetchError.message
        );

        finalUrl =
          url;

        isSecure =
          url
            .toLowerCase()
            .startsWith("https://");

      }


      // ======================================================
      // 3. FINAL DESTINATION
      // ======================================================

      const analyzedURL =
        finalUrl.toLowerCase();


      // ======================================================
      // 4. HTTPS
      // ======================================================

      if (!isSecure) {

        warnings.push(
          "URL does not use HTTPS"
        );

      }


      // ======================================================
      // 5. REDIRECT
      // ======================================================

      if (
        redirectDetected
      ) {

        if (
          safeRedirect
        ) {

          // Do NOT treat same-domain
          // redirects as suspicious.

          console.log(
            `Safe redirect: ${url} -> ${finalUrl}`
          );

        } else {

          warnings.push(
            `URL redirects to: ${finalUrl}`
          );

        }

      }


      // ======================================================
      // 6. SUSPICIOUS KEYWORDS
      // ======================================================

      const suspiciousWords = [

        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "signin",
        "sign-in",
        "bank",
        "confirm",
        "authentication",
        "wallet",
        "payment"

      ];


      const foundWords =
        suspiciousWords.filter(
          (word) =>
            analyzedURL.includes(
              word
            )
        );


      if (
        foundWords.length > 0
      ) {

        warnings.push(
          `Suspicious keyword(s): ${foundWords.join(
            ", "
          )}`
        );

      }


      // ======================================================
      // 7. IP ADDRESS
      // ======================================================

      const ipMatch =
        analyzedURL.match(
          /^https?:\/\/(\d{1,3}\.){3}\d{1,3}(?::\d+)?/
        );


      if (ipMatch) {

        warnings.push(
          "URL uses an IP address instead of a domain name"
        );

      }


      // ======================================================
      // 8. @ SYMBOL
      // ======================================================

      if (
        finalUrl.includes("@")
      ) {

        warnings.push(
          "URL contains an @ symbol, which can hide the real destination"
        );

      }


      // ======================================================
      // 9. URL LENGTH
      // ======================================================

      if (
        finalUrl.length > 100
      ) {

        warnings.push(
          "URL is unusually long"
        );

      }


      // ======================================================
      // 10. DOMAIN ANALYSIS
      // ======================================================

      let detectedLookAlike =
        false;

      let hostname =
        "";


      try {

        const parsedURL =
          new URL(finalUrl);


        hostname =
          parsedURL.hostname
            .toLowerCase()
            .replace(
              /^www\./,
              ""
            );


        // ----------------------------------------------------
        // SUBDOMAINS
        // ----------------------------------------------------

        const domainParts =
          hostname.split(".");


        if (
          domainParts.length >= 4
        ) {

          warnings.push(
            "URL contains an unusually large number of subdomains"
          );

        }


        // ----------------------------------------------------
        // TRUSTED DOMAINS
        // ----------------------------------------------------

        const trustedDomains = [

          "google.com",
          "paypal.com",
          "microsoft.com",
          "amazon.com",
          "apple.com",
          "facebook.com",
          "instagram.com",
          "linkedin.com",
          "github.com",
          "openai.com",
          "chatgpt.com"

        ];


        for (
          const trusted
          of trustedDomains
        ) {

          const trustedName =
            trusted.split(".")[0];


          if (
            hostname ===
              trusted ||
            hostname.endsWith(
              "." + trusted
            )
          ) {

            // Completely legitimate
            // trusted domain.

            continue;

          }


          if (
            hostname.includes(
              trustedName
            )
          ) {

            warnings.push(
              `Possible impersonation of trusted domain: ${trusted}`
            );

            break;

          }

        }


        // ----------------------------------------------------
        // LOOKALIKE PATTERNS
        // ----------------------------------------------------

        const lookAlikePatterns = [

          "paypa1",
          "paypai",
          "g00gle",
          "go0gle",
          "goog1e",
          "micros0ft",
          "micro5oft",
          "faceb00k",
          "arnazon",
          "amaz0n",
          "app1e",
          "github1"

        ];


        detectedLookAlike =
          lookAlikePatterns.some(
            (pattern) =>
              hostname.includes(
                pattern
              )
          );


        if (
          detectedLookAlike
        ) {

          warnings.push(
            "Possible typosquatting or homoglyph attack detected"
          );

        }


        // ----------------------------------------------------
        // HYPHENS
        // ----------------------------------------------------

        const hyphenCount =
          (
            hostname.match(
              /-/g
            ) || []
          ).length;


        if (
          hyphenCount >= 3
        ) {

          warnings.push(
            "Domain contains multiple hyphens"
          );

        }


        // ----------------------------------------------------
        // DIGITS
        // ----------------------------------------------------

        const digitCount =
          (
            hostname.match(
              /\d/g
            ) || []
          ).length;


        if (
          digitCount >= 3
        ) {

          warnings.push(
            "Domain contains an unusually high number of digits"
          );

        }

      } catch (urlError) {

        warnings.push(
          "Unable to properly parse the final URL"
        );

      }


      // ======================================================
      // 11. BRAND IMPERSONATION FROM PYTHON
      // ======================================================

      const brandImpersonation =
        mlResult.brand_impersonation ||
        null;


      const legitimateDomain =
        mlResult.legitimate_domain ===
        true;


      const officialBrand =
        mlResult.official_brand ||
        null;


      const officialDomain =
        mlResult.official_domain ||
        null;


      // ======================================================
      // 12. FINAL SCORE
      // ======================================================

      let finalScore =
        Number(
          mlResult.score
        ) || 0;


      let finalRisk =
        mlResult.risk ||
        "LOW RISK";


      finalScore =
        Math.max(
          0,
          Math.min(
            100,
            finalScore
          )
        );


      // ======================================================
      // 13. HEURISTIC BONUS
      // ======================================================

      let heuristicBonus =
        0;


      // HTTP
      if (
        !isSecure
      ) {

        heuristicBonus += 8;

      }


      // Suspicious words
      if (
        foundWords.length > 0
      ) {

        heuristicBonus +=
          Math.min(
            foundWords.length * 5,
            20
          );

      }


      // IP
      if (
        ipMatch
      ) {

        heuristicBonus += 15;

      }


      // @ symbol
      if (
        finalUrl.includes("@")
      ) {

        heuristicBonus += 15;

      }


      // Look-alike
      if (
        detectedLookAlike
      ) {

        heuristicBonus += 25;

      }


      // Brand impersonation
      if (
        brandImpersonation
      ) {

        heuristicBonus += 25;

      }


      // Excessive subdomains
      try {

        const parsed =
          new URL(finalUrl);


        if (
          parsed.hostname
            .split(".")
            .length >= 4
        ) {

          heuristicBonus += 8;

        }

      } catch (e) {

        // Ignore

      }


      // Apply heuristic score
      finalScore +=
        heuristicBonus;


      // ======================================================
      // 14. SAFE REDIRECT
      // ======================================================

      if (
        redirectDetected &&
        safeRedirect
      ) {

        // A same-domain redirect is
        // not a phishing indicator.

        finalScore =
          Math.max(
            0,
            finalScore - 8
          );

      }


      // ======================================================
      // 15. LEGITIMATE DOMAIN PROTECTION
      // ======================================================

      if (
        legitimateDomain
      ) {

        // Official domain gets a strong
        // safety override.

        finalScore =
          Math.min(
            finalScore,
            20
          );

      }


      // ======================================================
      // 16. BRAND IMPERSONATION PROTECTION
      // ======================================================

      if (
        brandImpersonation
      ) {

        finalScore =
          Math.max(
            finalScore,
            85
          );

      }


      // ======================================================
      // 17. LIMIT SCORE
      // ======================================================

      finalScore =
        Math.round(
          Math.max(
            0,
            Math.min(
              100,
              finalScore
            )
          )
        );


      // ======================================================
      // 18. FINAL RISK
      // ======================================================

      if (
        finalScore >= 70
      ) {

        finalRisk =
          "HIGH RISK";

      } else if (
        finalScore >= 40
      ) {

        finalRisk =
          "MEDIUM RISK";

      } else {

        finalRisk =
          "LOW RISK";

      }


      // ======================================================
      // 19. ADD BRAND WARNING
      // ======================================================

      if (
        brandImpersonation
      ) {

        const alreadyExists =
          warnings.some(
            (warning) =>
              warning
                .toLowerCase()
                .includes(
                  "impersonat"
                )
          );


        if (!alreadyExists) {

          warnings.push(
            `Possible ${brandImpersonation.attack_type} impersonating ${brandImpersonation.brand}`
          );

        }

      }


      // ======================================================
      // 20. LEGITIMATE DOMAIN MESSAGE
      // ======================================================

      if (
        legitimateDomain &&
        officialBrand
      ) {

        warnings.push(
          `Known legitimate domain: ${officialBrand}`
        );

      }


      // ======================================================
      // 21. SECURITY CHECKS
      // ======================================================

      const securityChecks = {

        https:
          isSecure,

        redirect_detected:
          redirectDetected,

        safe_redirect:
          safeRedirect,

        suspicious_keywords:
          foundWords,

        ip_address_detected:
          !!ipMatch,

        at_symbol_detected:
          finalUrl.includes("@"),

        typosquatting_detected:
          detectedLookAlike,

        brand_impersonation_detected:
          !!brandImpersonation,

        legitimate_domain:
          legitimateDomain

      };


      // ======================================================
      // 22. RESPONSE
      // ======================================================

      res.json({

        url:

          url,

        final_resolved_url:

          finalUrl,

        risk:

          finalRisk,

        score:

          finalScore,

        phishing_probability:

          mlResult.phishing_probability,

        features:

          mlResult.features,

        domain:

          mlResult.domain ||
          hostname,

        brand_impersonation:

          brandImpersonation,

        legitimate_domain:

          legitimateDomain,

        official_brand:

          officialBrand,

        official_domain:

          officialDomain,

        warnings:

          warnings,

        security_checks:

          securityChecks

      });


    } catch (error) {

      console.error(
        "URL analysis error:",
        error
      );


      res.status(500).json({

        error:
          "URL analysis failed",

        details:
          error.message

      });

    }

  }
);


// ============================================================
// START SERVER
// ============================================================

app.listen(
  PORT,
  () => {

    console.log(
      `PhishGuard backend running on http://localhost:${PORT}`
    );

  }
);