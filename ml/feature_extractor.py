import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "password",
    "credential",
    "payment",
    "billing",
    "confirm",
    "authenticate",
    "wallet",
    "bank",
    "suspend",
    "unlock",
    "recover",
    "reset",
    "urgent"
]


def normalize_url(url):

    url = url.strip()

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        url
    ):
        url = "http://" + url

    return url


def get_domain(url):

    try:

        parsed = urlparse(
            normalize_url(url)
        )

        return (
            parsed.hostname or ""
        ).lower().rstrip(".")

    except Exception:

        return ""


def extract_features(url):

    normalized = normalize_url(url)

    parsed = urlparse(normalized)

    domain = parsed.hostname or ""

    domain = domain.lower()

    url_lower = normalized.lower()

    domain_name = domain.split(".")[0]

    suspicious_count = sum(
        word in url_lower
        for word in SUSPICIOUS_WORDS
    )

    has_ip = bool(
        re.fullmatch(
            r"\d{1,3}(\.\d{1,3}){3}",
            domain
        )
    )

    return [
        len(url),

        int(parsed.scheme == "https"),

        int("@" in url),

        int(has_ip),

        url.count("-"),

        domain.count("."),

        sum(c.isdigit() for c in url),

        suspicious_count,

        max(domain.count(".") - 1, 0),

        len(
            re.findall(
                r"%[0-9a-fA-F]{2}",
                url
            )
        ),

        len(domain),

        len(domain_name),

        int("xn--" in domain),

        sum(
            ord(c) > 127
            for c in domain
        ),

        len(parsed.path),

        len(parsed.query),

        int("//" in parsed.path)
    ]


FEATURE_NAMES = [
    "url_length",
    "has_https",
    "has_at_symbol",
    "has_ip",
    "hyphen_count",
    "dot_count",
    "digit_count",
    "suspicious_word_count",
    "subdomain_count",
    "encoded_character_count",
    "domain_length",
    "domain_name_length",
    "has_punycode",
    "unicode_count",
    "path_length",
    "query_length",
    "double_slash_in_path"
]