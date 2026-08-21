# ============================================================
# PHISHGUARD-AI VISUAL / CONTENT DETECTOR
# ============================================================
#
# Detects:
#   1. Login page indicators
#   2. Payment page indicators
#   3. Brand names in page content
#   4. Possible brand impersonation
#   5. Suspicious forms
#   6. Suspicious page title
#
# Output is ALWAYS JSON so Node.js can safely read stdout.
# ============================================================

import sys
import json
import re
from urllib.parse import urlparse

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# ============================================================
# CONFIGURATION
# ============================================================

TIMEOUT = 10

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36"
)


# ============================================================
# KNOWN BRANDS
# ============================================================

BRANDS = {
    "google": [
        "google",
        "google.com"
    ],

    "paypal": [
        "paypal",
        "paypal.com"
    ],

    "microsoft": [
        "microsoft",
        "microsoft.com"
    ],

    "amazon": [
        "amazon",
        "amazon.com"
    ],

    "apple": [
        "apple",
        "apple.com"
    ],

    "facebook": [
        "facebook",
        "facebook.com"
    ],

    "instagram": [
        "instagram",
        "instagram.com"
    ],

    "linkedin": [
        "linkedin",
        "linkedin.com"
    ],

    "github": [
        "github",
        "github.com"
    ],

    "openai": [
        "openai",
        "openai.com"
    ],

    "chatgpt": [
        "chatgpt",
        "chatgpt.com"
    ]
}


# ============================================================
# LOGIN KEYWORDS
# ============================================================

LOGIN_KEYWORDS = [
    "login",
    "log in",
    "signin",
    "sign in",
    "sign-in",
    "username",
    "user name",
    "password",
    "forgot password",
    "forgot your password",
    "authentication",
    "authenticate",
    "verification",
    "verify your account",
    "account verification",
    "email address",
    "enter your password",
    "continue to login"
]


# ============================================================
# PAYMENT KEYWORDS
# ============================================================

PAYMENT_KEYWORDS = [
    "payment",
    "pay now",
    "checkout",
    "credit card",
    "debit card",
    "card number",
    "cvv",
    "cvc",
    "expiry date",
    "expiration date",
    "billing address",
    "bank account",
    "upi",
    "upi id",
    "net banking",
    "transaction",
    "wallet",
    "paypal",
    "payment method"
]


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "verify immediately",
    "verify now",
    "account suspended",
    "account locked",
    "urgent",
    "security alert",
    "confirm your identity",
    "confirm account",
    "update your account",
    "unusual activity",
    "suspicious activity",
    "limited access",
    "restore access",
    "click here",
    "act now"
]


# ============================================================
# HTML FETCH
# ============================================================

def fetch_page(url):

    try:

        request = Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/xml;q=0.9,*/*;q=0.8"
                )
            }
        )

        response = urlopen(
            request,
            timeout=TIMEOUT
        )

        final_url = response.geturl()

        content_type = (
            response.headers.get(
                "Content-Type",
                ""
            )
            .lower()
        )

        data = response.read(
            2 * 1024 * 1024
        )

        charset = "utf-8"

        match = re.search(
            r"charset=([A-Za-z0-9_-]+)",
            content_type
        )

        if match:

            charset = match.group(1)

        try:

            html = data.decode(
                charset,
                errors="ignore"
            )

        except Exception:

            html = data.decode(
                "utf-8",
                errors="ignore"
            )

        return {
            "success": True,
            "html": html,
            "final_url": final_url,
            "status": getattr(
                response,
                "status",
                200
            )
        }

    except HTTPError as error:

        return {
            "success": False,
            "error": (
                f"HTTP error {error.code}"
            )
        }

    except URLError as error:

        return {
            "success": False,
            "error": (
                f"Connection error: {error.reason}"
            )
        }

    except Exception as error:

        return {
            "success": False,
            "error": str(error)
        }


# ============================================================
# REMOVE HTML
# ============================================================

def html_to_text(html):

    if not html:

        return ""

    text = html

    # Remove scripts
    text = re.sub(
        r"<script\b[^>]*>.*?</script>",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL
    )

    # Remove styles
    text = re.sub(
        r"<style\b[^>]*>.*?</style>",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL
    )

    # Remove comments
    text = re.sub(
        r"<!--.*?-->",
        " ",
        text,
        flags=re.DOTALL
    )

    # Remove tags
    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    # Decode common HTML entities
    replacements = {
        "&nbsp;": " ",
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'"
    }

    for old, new in replacements.items():

        text = text.replace(
            old,
            new
        )

    # Normalize whitespace
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# EXTRACT TITLE
# ============================================================

def extract_title(html):

    if not html:

        return ""

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        flags=re.IGNORECASE | re.DOTALL
    )

    if not match:

        return ""

    title = match.group(1)

    title = re.sub(
        r"<[^>]+>",
        " ",
        title
    )

    title = re.sub(
        r"\s+",
        " ",
        title
    )

    return title.strip()


# ============================================================
# KEYWORD DETECTION
# ============================================================

def find_keywords(text, keywords):

    text_lower = text.lower()

    found = []

    for keyword in keywords:

        if keyword.lower() in text_lower:

            if keyword not in found:

                found.append(
                    keyword
                )

    return found


# ============================================================
# FORM DETECTION
# ============================================================

def detect_forms(html):

    if not html:

        return {
            "forms": 0,
            "password_forms": 0,
            "payment_forms": 0
        }

    forms = re.findall(
        r"<form\b[^>]*>.*?</form>",
        html,
        flags=re.IGNORECASE | re.DOTALL
    )

    password_forms = 0
    payment_forms = 0

    for form in forms:

        form_lower = form.lower()

        if re.search(
            r'type\s*=\s*["\']password["\']',
            form_lower
        ):

            password_forms += 1

        payment_words = [
            "card",
            "cvv",
            "cvc",
            "expiry",
            "expiration",
            "billing",
            "payment"
        ]

        if any(
            word in form_lower
            for word in payment_words
        ):

            payment_forms += 1

    return {
        "forms": len(forms),
        "password_forms": password_forms,
        "payment_forms": payment_forms
    }


# ============================================================
# BRAND DETECTION
# ============================================================

def detect_brands(text, title):

    combined = (
        text + " " + title
    ).lower()

    detected = []

    for brand, names in BRANDS.items():

        for name in names:

            if name.lower() in combined:

                if brand not in detected:

                    detected.append(
                        brand
                    )

                break

    return detected


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_domain(url):

    try:

        parsed = urlparse(
            url
        )

        hostname = parsed.hostname

        if not hostname:

            return ""

        return hostname.lower()

    except Exception:

        return ""


# ============================================================
# REGISTERED DOMAIN
# ============================================================

def get_registered_domain(domain):

    if not domain:

        return ""

    parts = domain.split(".")

    if len(parts) < 2:

        return domain

    common_second_level = {
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
    }

    last_two = ".".join(
        parts[-2:]
    )

    if last_two in common_second_level:

        if len(parts) >= 3:

            return ".".join(
                parts[-3:]
            )

    return ".".join(
        parts[-2:]
    )


# ============================================================
# BRAND DOMAIN MATCH
# ============================================================

def domain_matches_brand(
    domain,
    brand
):

    registered = (
        get_registered_domain(
            domain
        )
    )

    brand_names = BRANDS.get(
        brand,
        []
    )

    for name in brand_names:

        name = name.lower()

        if (
            registered == name
            or registered.startswith(
                name + "."
            )
        ):

            return True

        if registered.startswith(
            name
        ):

            return True

    return False


# ============================================================
# POSSIBLE BRAND IMPERSONATION
# ============================================================

def detect_brand_impersonation(
    domain,
    brands_detected
):

    if not domain:

        return []

    registered = (
        get_registered_domain(
            domain
        )
    )

    results = []

    for brand in brands_detected:

        official_domains = BRANDS.get(
            brand,
            []
        )

        legitimate = False

        for official in official_domains:

            if registered == official:

                legitimate = True

                break

        if legitimate:

            continue

        results.append({
            "brand": brand,
            "domain": registered,
            "reason": (
                "Brand name appears in page content "
                "but domain is not the official domain"
            )
        })

    return results


# ============================================================
# LOGO / IMAGE DETECTION
# ============================================================

def detect_brand_images(
    html,
    brands_detected
):

    if not html:

        return []

    images = re.findall(
        r"<img\b[^>]*(?:src|alt)\s*=\s*['\"][^'\"]*['\"][^>]*>",
        html,
        flags=re.IGNORECASE
    )

    detected = []

    for image in images:

        image_lower = image.lower()

        for brand in brands_detected:

            brand_lower = brand.lower()

            if (
                brand_lower in image_lower
                and brand not in detected
            ):

                detected.append(
                    brand
                )

    return detected


# ============================================================
# SCORE CALCULATION
# ============================================================

def calculate_visual_score(
    login_page,
    payment_page,
    suspicious_keywords,
    brands_detected,
    impersonations,
    password_forms,
    payment_forms,
    brand_images
):

    score = 0
    warnings = []

    # --------------------------------------------------------
    # LOGIN
    # --------------------------------------------------------

    if login_page:

        score += 15

        warnings.append(
            "Login-related content detected"
        )

    # --------------------------------------------------------
    # PASSWORD FORM
    # --------------------------------------------------------

    if password_forms > 0:

        score += 15

        warnings.append(
            "Password input detected on the page"
        )

    # --------------------------------------------------------
    # PAYMENT
    # --------------------------------------------------------

    if payment_page:

        score += 15

        warnings.append(
            "Payment-related content detected"
        )

    # --------------------------------------------------------
    # PAYMENT FORM
    # --------------------------------------------------------

    if payment_forms > 0:

        score += 15

        warnings.append(
            "Payment information form detected"
        )

    # --------------------------------------------------------
    # SUSPICIOUS WORDS
    # --------------------------------------------------------

    if suspicious_keywords:

        score += min(
            len(suspicious_keywords) * 5,
            20
        )

        warnings.append(
            "Suspicious security-related language detected"
        )

    # --------------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------------

    if impersonations:

        score += 30

        for item in impersonations:

            warnings.append(
                "Possible "
                + item["brand"]
                + " brand impersonation detected"
            )

    # --------------------------------------------------------
    # BRAND IMAGE
    # --------------------------------------------------------

    if brand_images:

        score += 10

        warnings.append(
            "Brand-related image/logo reference detected"
        )

    # --------------------------------------------------------
    # LIMIT
    # --------------------------------------------------------

    score = min(
        100,
        score
    )

    return score, warnings


# ============================================================
# MAIN DETECTION
# ============================================================

def analyze_url(url):

    domain = get_domain(
        url
    )

    result = {
        "available": False,
        "url": url,
        "domain": domain,
        "final_url": url,
        "login_page_detected": False,
        "login_keywords": [],
        "payment_page_detected": False,
        "payment_keywords": [],
        "suspicious_keywords": [],
        "brands_detected": [],
        "brand_images_detected": [],
        "brand_impersonation": [],
        "forms": 0,
        "password_forms": 0,
        "payment_forms": 0,
        "visual_score": 0,
        "warnings": []
    }

    # --------------------------------------------------------
    # FETCH PAGE
    # --------------------------------------------------------

    page = fetch_page(
        url
    )

    if not page["success"]:

        result["warnings"].append(
            "Unable to fetch webpage: "
            + page.get(
                "error",
                "Unknown error"
            )
        )

        return result

    result["available"] = True

    result["final_url"] = (
        page.get(
            "final_url",
            url
        )
    )

    html = page.get(
        "html",
        ""
    )

    # --------------------------------------------------------
    # TEXT
    # --------------------------------------------------------

    text = html_to_text(
        html
    )

    title = extract_title(
        html
    )

    # --------------------------------------------------------
    # LOGIN
    # --------------------------------------------------------

    login_keywords = find_keywords(
        text,
        LOGIN_KEYWORDS
    )

    result["login_keywords"] = (
        login_keywords
    )

    result["login_page_detected"] = (
        len(login_keywords) > 0
    )

    # --------------------------------------------------------
    # PAYMENT
    # --------------------------------------------------------

    payment_keywords = find_keywords(
        text,
        PAYMENT_KEYWORDS
    )

    result["payment_keywords"] = (
        payment_keywords
    )

    result["payment_page_detected"] = (
        len(payment_keywords) > 0
    )

    # --------------------------------------------------------
    # SUSPICIOUS WORDS
    # --------------------------------------------------------

    suspicious_keywords = find_keywords(
        text,
        SUSPICIOUS_KEYWORDS
    )

    result["suspicious_keywords"] = (
        suspicious_keywords
    )

    # --------------------------------------------------------
    # BRANDS
    # --------------------------------------------------------

    brands_detected = detect_brands(
        text,
        title
    )

    result["brands_detected"] = (
        brands_detected
    )

    # --------------------------------------------------------
    # FORMS
    # --------------------------------------------------------

    form_info = detect_forms(
        html
    )

    result["forms"] = (
        form_info["forms"]
    )

    result["password_forms"] = (
        form_info["password_forms"]
    )

    result["payment_forms"] = (
        form_info["payment_forms"]
    )

    # --------------------------------------------------------
    # BRAND IMAGE / LOGO REFERENCES
    # --------------------------------------------------------

    brand_images = detect_brand_images(
        html,
        brands_detected
    )

    result["brand_images_detected"] = (
        brand_images
    )

    # --------------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------------

    impersonations = (
        detect_brand_impersonation(
            domain,
            brands_detected
        )
    )

    result["brand_impersonation"] = (
        impersonations
    )

    # --------------------------------------------------------
    # VISUAL SCORE
    # --------------------------------------------------------

    visual_score, warnings = (
        calculate_visual_score(
            login_page=result[
                "login_page_detected"
            ],
            payment_page=result[
                "payment_page_detected"
            ],
            suspicious_keywords=suspicious_keywords,
            brands_detected=brands_detected,
            impersonations=impersonations,
            password_forms=form_info[
                "password_forms"
            ],
            payment_forms=form_info[
                "payment_forms"
            ],
            brand_images=brand_images
        )
    )

    result["visual_score"] = (
        visual_score
    )

    result["warnings"].extend(
        warnings
    )

    # Remove duplicate warnings
    result["warnings"] = list(
        dict.fromkeys(
            result["warnings"]
        )
    )

    return result


# ============================================================
# COMMAND LINE
# ============================================================

if len(sys.argv) < 2:

    print(
        json.dumps({
            "available": False,
            "error": "URL argument is required"
        })
    )

    sys.exit(1)


url = sys.argv[1].strip()


# ============================================================
# ADD HTTP IF REQUIRED
# ============================================================

if not url.lower().startswith(
    (
        "http://",
        "https://"
    )
):

    url = (
        "http://"
        + url
    )


# ============================================================
# RUN
# ============================================================

try:

    result = analyze_url(
        url
    )

    print(
        json.dumps(
            result,
            ensure_ascii=False
        )
    )

except Exception as error:

    print(
        json.dumps({
            "available": False,
            "url": url,
            "error": str(error)
        })
    )

    sys.exit(1)