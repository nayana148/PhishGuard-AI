import sys
import os
import json
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
    }))

    sys.exit(1)


try:

    model = joblib.load(
        MODEL_FILE
    )

except Exception as error:

    print(json.dumps({
        "error": f"Could not load model: {str(error)}"
    }))

    sys.exit(1)


# ============================================================
# LOAD BRANDS
# ============================================================

if not os.path.exists(BRANDS_FILE):

    print(json.dumps({
        "error": "brands.json not found."
    }))

    sys.exit(1)


try:

    with open(
        BRANDS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        BRANDS = json.load(file)

except Exception as error:

    print(json.dumps({
        "error": f"Could not load brands.json: {str(error)}"
    }))

    sys.exit(1)


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

            if domain == official_domain:

                return (
                    True,
                    brand,
                    official_domain
                )

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


    # --------------------------------------------------------
    # CHECK EACH BRAND
    # --------------------------------------------------------

    for brand, official_domains in BRANDS.items():

        brand = brand.lower()


        # ----------------------------------------------------
        # SKIP REAL OFFICIAL DOMAIN
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
        # SIMILARITY
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
        # DETECTION
        # ----------------------------------------------------

        suspicious = False

        attack_type = None


        # Number/look-alike substitution
        if normalized_name != raw_name:

            if normalized_similarity >= 0.80:

                suspicious = True

                attack_type = (
                    "homoglyph/look-alike"
                )


        # Very close spelling
        if (
            normalized_similarity >= 0.85
            and edit_distance <= 2
        ):

            suspicious = True

            attack_type = (
                "typosquatting"
            )


        # Repeated-character manipulation
        if compressed_similarity >= 0.90:

            suspicious = True

            attack_type = (
                "repeated-character manipulation"
            )


        # Raw similarity
        if raw_similarity >= 0.90:

            suspicious = True

            attack_type = (
                "typosquatting"
            )


        # ----------------------------------------------------
        # SAVE BEST MATCH
        # ----------------------------------------------------

        if suspicious:

            candidate = {

                "brand":
                    brand,

                "attack_type":
                    attack_type,

                "similarity":
                    round(
                        max(
                            raw_similarity,
                            normalized_similarity,
                            compressed_similarity
                        ),
                        3
                    ),

                "edit_distance":
                    edit_distance

            }


            if (
                best_match is None
                or
                candidate["similarity"]
                >
                best_match["similarity"]
            ):

                best_match = candidate


    return best_match


# ============================================================
# GET URL
# ============================================================

if len(sys.argv) < 2:

    print(json.dumps({
        "error": "URL argument is required"
    }))

    sys.exit(1)


url = sys.argv[1].strip()


# ============================================================
# NORMALIZE URL
# ============================================================

if not url.lower().startswith(
    ("http://", "https://")
):

    url = "http://" + url


# ============================================================
# MAIN PREDICTION
# ============================================================

try:

    # --------------------------------------------------------
    # EXTRACT FEATURES
    # --------------------------------------------------------

    features = extract_features(
        url
    )


    # IMPORTANT:
    # extract_features() returns a LIST,
    # not a dictionary.

    feature_values = features


    # --------------------------------------------------------
    # ML PREDICTION
    # --------------------------------------------------------

    prediction = model.predict(
        [feature_values]
    )[0]


    # --------------------------------------------------------
    # PHISHING PROBABILITY
    # --------------------------------------------------------

    phishing_probability = None


    if hasattr(
        model,
        "predict_proba"
    ):

        probabilities = (
            model.predict_proba(
                [feature_values]
            )[0]
        )

        classes = list(
            model.classes_
        )


        phishing_index = None


        for index, class_value in enumerate(classes):

            class_string = str(
                class_value
            ).lower()


            if class_string in [
                "1",
                "phishing",
                "malicious",
                "bad",
                "true"
            ]:

                phishing_index = index

                break


        if phishing_index is not None:

            phishing_probability = (
                float(
                    probabilities[
                        phishing_index
                    ]
                )
                * 100
            )

        elif len(probabilities) > 1:

            phishing_probability = (
                float(
                    probabilities[-1]
                )
                * 100
            )

        else:

            phishing_probability = (
                float(
                    probabilities[0]
                )
                * 100
            )


    else:

        phishing_probability = (
            100.0
            if prediction == 1
            else 0.0
        )


    phishing_probability = round(
        phishing_probability,
        2
    )


    # --------------------------------------------------------
    # DOMAIN ANALYSIS
    # --------------------------------------------------------

    domain = get_domain(
        url
    )


    legitimate, brand, official_domain = (
        is_known_legitimate_domain(
            domain
        )
    )


    impersonation = None


    if not legitimate:

        impersonation = (
            detect_impersonation(
                domain
            )
        )


    # --------------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------------

    score = round(
        phishing_probability
    )


    # --------------------------------------------------------
    # TYPOSQUATTING BOOST
    # --------------------------------------------------------

    if impersonation:

        score = max(
            score,
            85
        )


    # --------------------------------------------------------
    # LEGITIMATE DOMAIN PROTECTION
    # --------------------------------------------------------

    if legitimate:

        score = min(
            score,
            20
        )


    # --------------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------------

    score = max(
        0,
        min(
            100,
            score
        )
    )


    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    if score >= 70:

        risk = "HIGH RISK"

    elif score >= 40:

        risk = "MEDIUM RISK"

    else:

        risk = "LOW RISK"


    # --------------------------------------------------------
    # WARNINGS
    # --------------------------------------------------------

    warnings = []


    if impersonation:

        warnings.append(
            "Possible "
            + impersonation["attack_type"]
            + " impersonating "
            + impersonation["brand"]
        )


    if legitimate:

        warnings.append(
            "Known legitimate domain: "
            + str(brand)
        )


    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    result = {

        "risk":
            risk,

        "score":
            score,

        "phishing_probability":
            phishing_probability,

        "features":
            features,

        "domain":
            domain,

        "brand_impersonation":
            impersonation,

        "legitimate_domain":
            legitimate,

        "official_brand":
            brand,

        "official_domain":
            official_domain,

        "warnings":
            warnings

    }


    # ========================================================
    # IMPORTANT
    # Node.js reads stdout and expects JSON.
    # ========================================================

    print(
        json.dumps(
            result,
            ensure_ascii=False
        )
    )


except Exception as error:

    print(
        json.dumps({
            "error":
                str(error)
        })
    )

    sys.exit(1)