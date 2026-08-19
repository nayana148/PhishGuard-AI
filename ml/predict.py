import sys
import os
import json
import re
from urllib.parse import urlsplit

import joblib

from feature_extractor import extract_features


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "model.pkl"
)

BRANDS_FILE = os.path.join(
    BASE_DIR,
    "brands.json"
)


# ============================================================
# LOAD MODEL
# ============================================================

if not os.path.exists(MODEL_FILE):

    print(json.dumps({
        "error": "model.pkl not found. Run train.py first."
    }, indent=2))

    sys.exit(1)


model = joblib.load(
    MODEL_FILE
)


# ============================================================
# LOAD BRANDS
# ============================================================

if not os.path.exists(BRANDS_FILE):

    print(json.dumps({
        "error": "brands.json not found."
    }, indent=2))

    sys.exit(1)


with open(
    BRANDS_FILE,
    "r",
    encoding="utf-8"
) as file:

    BRANDS = json.load(file)


# ============================================================
# LOOKALIKE CHARACTER MAP
# ============================================================

LOOKALIKE_MAP = {

    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b"

}


# ============================================================
# NORMALIZE LOOKALIKE CHARACTERS
# ============================================================

def normalize_lookalikes(text):

    result = []

    for char in text.lower():

        if char in LOOKALIKE_MAP:

            result.append(
                LOOKALIKE_MAP[char]
            )

        else:

            result.append(char)

    return "".join(result)


# ============================================================
# COMPRESS REPEATED CHARACTERS
# ============================================================

def compress_repeated_characters(text):

    if not text:

        return ""

    result = [
        text[0]
    ]

    for char in text[1:]:

        if char != result[-1]:

            result.append(
                char
            )

    return "".join(result)


# ============================================================
# LEVENSHTEIN DISTANCE
# ============================================================

def levenshtein(a, b):

    if a == b:

        return 0

    if len(a) < len(b):

        a, b = b, a

    previous = list(
        range(len(b) + 1)
    )

    for i, char_a in enumerate(
        a,
        start=1
    ):

        current = [i]

        for j, char_b in enumerate(
            b,
            start=1
        ):

            insertion = (
                current[j - 1] + 1
            )

            deletion = (
                previous[j] + 1
            )

            substitution = (
                previous[j - 1]
                + (char_a != char_b)
            )

            current.append(
                min(
                    insertion,
                    deletion,
                    substitution
                )
            )

        previous = current

    return previous[-1]


# ============================================================
# SIMILARITY
# ============================================================

def similarity(a, b):

    if not a or not b:

        return 0.0

    distance = levenshtein(
        a,
        b
    )

    return 1 - (
        distance /
        max(
            len(a),
            len(b)
        )
    )


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_domain(url):

    try:

        parsed = urlsplit(
            url
        )

        hostname = parsed.hostname

        if not hostname:

            return ""

        return hostname.lower().rstrip(".")

    except Exception:

        return ""


# ============================================================
# REGISTERED DOMAIN
# ============================================================

def get_registered_domain(domain):

    parts = domain.split(".")

    if len(parts) < 2:

        return domain

    # Handle common two-part country domains
    # such as google.co.in

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
# CHECK KNOWN LEGITIMATE DOMAIN
# ============================================================

def is_known_legitimate_domain(domain):

    if not domain:

        return False, None, None

    for brand, official_domains in BRANDS.items():

        for official_domain in official_domains:

            official_domain = (
                official_domain.lower()
            )

            # Exact official domain
            if domain == official_domain:

                return (
                    True,
                    brand,
                    official_domain
                )

            # Legitimate subdomain
            if domain.endswith(
                "." + official_domain
            ):

                return (
                    True,
                    brand,
                    official_domain
                )

    return (
        False,
        None,
        None
    )


# ============================================================
# BRAND IMPERSONATION
# ============================================================

def detect_impersonation(domain):

    if not domain:

        return None

    registered_domain = (
        get_registered_domain(
            domain
        )
    )

    domain_parts = (
        registered_domain.split(".")
    )

    if not domain_parts:

        return None

    domain_name = (
        domain_parts[0]
    )

    raw_name = domain_name

    normalized_name = (
        normalize_lookalikes(
            raw_name
        )
    )

    compressed_name = (
        compress_repeated_characters(
            normalized_name
        )
    )

    best_match = None

    for brand, official_domains in BRANDS.items():

        brand = brand.lower()

        # ----------------------------------------------------
        # Exact legitimate brand
        # ----------------------------------------------------

        legitimate_exact = False

        for official_domain in official_domains:

            official_registered = (
                get_registered_domain(
                    official_domain.lower()
                )
            )

            official_name = (
                official_registered.split(".")[0]
            )

            if domain_name == official_name:

                legitimate_exact = True

                break

        if legitimate_exact:

            continue

        # ----------------------------------------------------
        # Similarity calculations
        # ----------------------------------------------------

        raw_similarity = similarity(
            raw_name,
            brand
        )

        normalized_similarity = similarity(
            normalized_name,
            brand
        )

        compressed_brand = (
            compress_repeated_characters(
                brand
            )
        )

        compressed_similarity = similarity(
            compressed_name,
            compressed_brand
        )

        edit_distance = levenshtein(
            normalized_name,
            brand
        )

        # ----------------------------------------------------
        # Detection
        # ----------------------------------------------------

        suspicious = False

        attack_type = None

        # Character substitution
        if normalized_similarity >= 0.80:

            suspicious = True

            attack_type = (
                "character substitution / lookalike"
            )

        # Repeated characters
        elif compressed_similarity >= 0.90:

            suspicious = True

            attack_type = (
                "repeated-character typosquatting"
            )

        # Small edit distance
        elif (
            edit_distance <= 2
            and len(brand) >= 5
        ):

            suspicious = True

            attack_type = (
                "character insertion/deletion/substitution"
            )

        if suspicious:

            candidate = {

                "brand":
                    brand,

                "official_domain":
                    official_domains[0],

                "raw_similarity":
                    round(
                        raw_similarity,
                        3
                    ),

                "normalized_similarity":
                    round(
                        normalized_similarity,
                        3
                    ),

                "compressed_similarity":
                    round(
                        compressed_similarity,
                        3
                    ),

                "edit_distance":
                    edit_distance,

                "attack_type":
                    attack_type
            }

            if (
                best_match is None
                or candidate[
                    "normalized_similarity"
                ]
                >
                best_match[
                    "normalized_similarity"
                ]
            ):

                best_match = candidate

    # --------------------------------------------------------
    # Suspicious brand in subdomain
    # --------------------------------------------------------

    subdomain_parts = domain.split(
        "."
    )[:-2]

    for brand, official_domains in BRANDS.items():

        brand = brand.lower()

        if brand in subdomain_parts:

            # If this isn't actually an official
            # domain, it is suspicious.

            is_official = False

            for official_domain in official_domains:

                if domain == official_domain:

                    is_official = True

                elif domain.endswith(
                    "." + official_domain
                ):

                    is_official = True

            if not is_official:

                candidate = {

                    "brand":
                        brand,

                    "official_domain":
                        official_domains[0],

                    "raw_similarity":
                        0.0,

                    "normalized_similarity":
                        0.0,

                    "compressed_similarity":
                        0.0,

                    "edit_distance":
                        0,

                    "attack_type":
                        "brand used in suspicious subdomain"
                }

                if best_match is None:

                    best_match = candidate

    return best_match


# ============================================================
# UNICODE ANALYSIS
# ============================================================

def analyze_unicode(domain):

    unicode_chars = [

        char

        for char in domain

        if ord(char) > 127

    ]

    return {

        "unicode_detected":
            len(unicode_chars) > 0,

        "punycode_detected":
            "xn--" in domain.lower(),

        "unicode_characters":
            len(unicode_chars)

    }


# ============================================================
# SAFE ML PREDICTION
# ============================================================

def get_ml_result(features):

    try:

        prediction = int(
            model.predict(
                [features]
            )[0]
        )

        probabilities = (
            model.predict_proba(
                [features]
            )[0]
        )

        # Our model convention:
        # 0 = legitimate
        # 1 = phishing

        if 1 in model.classes_:

            phishing_index = list(
                model.classes_
            ).index(1)

            probability = (
                probabilities[
                    phishing_index
                ] * 100
            )

        else:

            probability = 100.0 if (
                prediction == 1
            ) else 0.0

        return (
            prediction,
            float(probability)
        )

    except Exception:

        return (
            0,
            0.0
        )


# ============================================================
# MAIN PREDICTION
# ============================================================

def predict(url):

    # --------------------------------------------------------
    # Domain
    # --------------------------------------------------------

    domain = get_domain(
        url
    )

    # --------------------------------------------------------
    # Features
    # --------------------------------------------------------

    features = extract_features(
        url
    )

    # --------------------------------------------------------
    # Known legitimate domain
    # --------------------------------------------------------

    known_legitimate, legitimate_brand, official_domain = (
        is_known_legitimate_domain(
            domain
        )
    )

    # --------------------------------------------------------
    # Unicode
    # --------------------------------------------------------

    unicode_analysis = (
        analyze_unicode(
            domain
        )
    )

    # --------------------------------------------------------
    # Impersonation
    # --------------------------------------------------------

    impersonation = (
        detect_impersonation(
            domain
        )
    )

    # --------------------------------------------------------
    # ML
    # --------------------------------------------------------

    ml_prediction, ml_probability = (
        get_ml_result(
            features
        )
    )

    reasons = []

    # ========================================================
    # DECISION 1
    # KNOWN LEGITIMATE DOMAIN
    # ========================================================

    if known_legitimate:

        risk = "LOW"

        score = 0

        phishing_probability = 0.0

        reasons.append(
            "Domain matches a known legitimate domain"
        )

        return {

            "risk":
                risk,

            "score":
                score,

            "phishing_probability":
                phishing_probability,

            "domain":
                domain,

            "ml_prediction":
                ml_prediction,

            "impersonation":
                None,

            "known_legitimate":
                True,

            "legitimate_brand":
                legitimate_brand,

            "official_domain":
                official_domain,

            "unicode_analysis":
                unicode_analysis,

            "features":
                features,

            "reasons":
                reasons
        }

    # ========================================================
    # DECISION 2
    # IMPERSONATION
    # ========================================================

    if impersonation:

        score = 90

        # Stronger score for exact/near exact
        # repeated-character attacks

        if (
            impersonation.get(
                "compressed_similarity",
                0
            ) >= 0.95
        ):

            score = 95

        if (
            impersonation.get(
                "normalized_similarity",
                0
            ) >= 0.90
        ):

            score = 98

        risk = "HIGH"

        phishing_probability = float(
            score
        )

        reasons.append(
            "Possible impersonation of "
            + impersonation["brand"]
        )

        reasons.append(
            "Domain resembles "
            + impersonation["official_domain"]
        )

        reasons.append(
            "Attack type: "
            + impersonation["attack_type"]
        )

        return {

            "risk":
                risk,

            "score":
                score,

            "phishing_probability":
                phishing_probability,

            "domain":
                domain,

            "ml_prediction":
                ml_prediction,

            "ml_probability":
                round(
                    ml_probability,
                    2
                ),

            "impersonation":
                impersonation,

            "known_legitimate":
                False,

            "unicode_analysis":
                unicode_analysis,

            "features":
                features,

            "reasons":
                reasons
        }

    # ========================================================
    # DECISION 3
    # GENERAL ML / SECURITY SIGNALS
    # ========================================================

    score = ml_probability

    if ml_prediction == 1:

        reasons.append(
            "Machine-learning model detected phishing characteristics"
        )

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    if features[3]:

        score = max(
            score,
            70
        )

        reasons.append(
            "URL uses an IP address"
        )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if features[2]:

        score = max(
            score,
            75
        )

        reasons.append(
            "URL contains an @ symbol"
        )

    # --------------------------------------------------------
    # Suspicious words
    # --------------------------------------------------------

    if features[7] > 0:

        score = max(
            score,
            min(
                40 + features[7] * 10,
                75
            )
        )

        reasons.append(
            "Suspicious account/security words detected"
        )

    # --------------------------------------------------------
    # Punycode
    # --------------------------------------------------------

    if unicode_analysis[
        "punycode_detected"
    ]:

        score = max(
            score,
            70
        )

        reasons.append(
            "Domain uses Punycode"
        )

    # --------------------------------------------------------
    # Unicode
    # --------------------------------------------------------

    if unicode_analysis[
        "unicode_detected"
    ]:

        score = max(
            score,
            70
        )

        reasons.append(
            "Domain contains Unicode characters"
        )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    score = min(
        round(score),
        100
    )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    if score >= 60:

        risk = "HIGH"

    elif score >= 30:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    # --------------------------------------------------------
    # No reasons
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "No major phishing indicators detected"
        )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {

        "risk":
            risk,

        "score":
            score,

        "phishing_probability":
            round(
                ml_probability,
                2
            ),

        "domain":
            domain,

        "ml_prediction":
            ml_prediction,

        "ml_probability":
            round(
                ml_probability,
                2
            ),

        "impersonation":
            impersonation,

        "known_legitimate":
            False,

        "unicode_analysis":
            unicode_analysis,

        "features":
            features,

        "reasons":
            reasons
    }


# ============================================================
# COMMAND LINE
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            json.dumps(
                {
                    "error":
                        "URL is required"
                },
                indent=2
            )
        )

        sys.exit(1)

    url = sys.argv[1]

    result = predict(
        url
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )