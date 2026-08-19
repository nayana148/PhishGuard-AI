import sys
import subprocess
import json


# ============================================================
# WINDOWS UTF-8 SUPPORT
# ============================================================

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ============================================================
# PHISHGUARD AUTOMATED TEST SUITE
# ============================================================

TESTS = [

    # ========================================================
    # LEGITIMATE WEBSITES
    # ========================================================

    {
        "name": "Google",
        "url": "https://google.com",
        "expected": "LOW"
    },

    {
        "name": "Microsoft",
        "url": "https://microsoft.com",
        "expected": "LOW"
    },

    {
        "name": "Amazon",
        "url": "https://amazon.com",
        "expected": "LOW"
    },

    {
        "name": "Apple",
        "url": "https://apple.com",
        "expected": "LOW"
    },

    {
        "name": "PayPal",
        "url": "https://paypal.com",
        "expected": "LOW"
    },

    {
        "name": "GitHub",
        "url": "https://github.com",
        "expected": "LOW"
    },

    {
        "name": "Instagram",
        "url": "https://instagram.com",
        "expected": "LOW"
    },

    {
        "name": "Netflix",
        "url": "https://netflix.com",
        "expected": "LOW"
    },


    # ========================================================
    # GOOGLE TYPOSQUATTING
    # ========================================================

    {
        "name": "Google repeated character",
        "url": "https://gooooogle.com",
        "expected": "HIGH"
    },

    {
        "name": "Google number substitution",
        "url": "https://g00gle.com",
        "expected": "HIGH"
    },

    {
        "name": "Google missing character",
        "url": "https://googel.com",
        "expected": "HIGH"
    },


    # ========================================================
    # MICROSOFT TYPOSQUATTING
    # ========================================================

    {
        "name": "Microsoft repeated character",
        "url": "https://microssoft.com",
        "expected": "HIGH"
    },

    {
        "name": "Microsoft number substitution",
        "url": "https://micr0soft.com",
        "expected": "HIGH"
    },


    # ========================================================
    # AMAZON TYPOSQUATTING
    # ========================================================

    {
        "name": "Amazon number substitution",
        "url": "https://amaz0n.com",
        "expected": "HIGH"
    },

    {
        "name": "Amazon repeated character",
        "url": "https://amaazon.com",
        "expected": "HIGH"
    },


    # ========================================================
    # PAYPAL TYPOSQUATTING
    # ========================================================

    {
        "name": "PayPal number substitution",
        "url": "https://paypa1.com",
        "expected": "HIGH"
    },

    {
        "name": "PayPal repeated character",
        "url": "https://paypall.com",
        "expected": "HIGH"
    },


    # ========================================================
    # APPLE TYPOSQUATTING
    # ========================================================

    {
        "name": "Apple number substitution",
        "url": "https://app1e.com",
        "expected": "HIGH"
    },


    # ========================================================
    # GITHUB TYPOSQUATTING
    # ========================================================

    {
        "name": "GitHub repeated character",
        "url": "https://githuub.com",
        "expected": "HIGH"
    },


    # ========================================================
    # INSTAGRAM TYPOSQUATTING
    # ========================================================

    {
        "name": "Instagram repeated character",
        "url": "https://instagrram.com",
        "expected": "HIGH"
    },


    # ========================================================
    # NETFLIX TYPOSQUATTING
    # ========================================================

    {
        "name": "Netflix number substitution",
        "url": "https://netfl1x.com",
        "expected": "HIGH"
    },


    # ========================================================
    # DOMAIN ABUSE
    # ========================================================

    {
        "name": "Google inside malicious domain",
        "url": "https://google.com.evil-site.com",
        "expected": "HIGH"
    },

    {
        "name": "Fake Google login",
        "url": "https://google-login-verification.com",
        "expected": "HIGH"
    },

    {
        "name": "Fake Microsoft login",
        "url": "https://microsoft-login-security.com",
        "expected": "HIGH"
    },


    # ========================================================
    # IP ADDRESS
    # ========================================================

    {
        "name": "IP address",
        "url": "http://192.168.1.100/login",
        "expected": "HIGH"
    },


    # ========================================================
    # SUSPICIOUS URL
    # ========================================================

    {
        "name": "Account verification",
        "url": "http://example.com/verify-account-login",
        "expected": "HIGH"
    },

    {
        "name": "Password verification",
        "url": "http://example.com/secure-login-password",
        "expected": "HIGH"
    },


    # ========================================================
    # AT SYMBOL ATTACK
    # ========================================================

    {
        "name": "At symbol attack",
        "url": "https://google.com@evil.com",
        "expected": "HIGH"
    },


    # ========================================================
    # PUNYCODE ATTACK
    # ========================================================

    {
        "name": "Punycode domain",
        "url": "https://xn--80ak6aa92e.com",
        "expected": "HIGH"
    }
]


# ============================================================
# RUN PHISHGUARD
# ============================================================

def run_detector(url):

    try:

        process = subprocess.run(
            [
                "py",
                "ml\\predict.py",
                url
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        output = process.stdout.strip()

        if not output:

            return {
                "risk": "ERROR",
                "error": process.stderr.strip()
            }

        try:

            return json.loads(output)

        except json.JSONDecodeError:

            return {
                "risk": "ERROR",
                "error": output
            }

    except Exception as error:

        return {
            "risk": "ERROR",
            "error": str(error)
        }


# ============================================================
# START TESTING
# ============================================================

print()
print("=" * 80)
print("PHISHGUARD AUTOMATED SECURITY TEST")
print("=" * 80)
print()


passed = 0
failed = 0

failed_tests = []


# ============================================================
# RUN ALL TESTS
# ============================================================

for number, test in enumerate(TESTS, start=1):

    result = run_detector(
        test["url"]
    )

    actual = result.get(
        "risk",
        "ERROR"
    )

    expected = test["expected"]


    # --------------------------------------------------------
    # PASS
    # --------------------------------------------------------

    if actual == expected:

        status = "PASS"

        passed += 1


    # --------------------------------------------------------
    # FAIL
    # --------------------------------------------------------

    else:

        status = "FAIL"

        failed += 1

        failed_tests.append({

            "number": number,
            "name": test["name"],
            "url": test["url"],
            "expected": expected,
            "actual": actual,
            "result": result

        })


    # --------------------------------------------------------
    # DISPLAY RESULT
    # --------------------------------------------------------

    print(
        f"[{status}] "
        f"{number:02d}. "
        f"{test['name']}"
    )

    print(
        f"     URL      : "
        f"{test['url']}"
    )

    print(
        f"     Expected : "
        f"{expected}"
    )

    print(
        f"     Actual   : "
        f"{actual}"
    )


    # --------------------------------------------------------
    # IMPERSONATION INFORMATION
    # --------------------------------------------------------

    impersonation = result.get(
        "impersonation"
    )

    if impersonation:

        print(
            f"     Brand    : "
            f"{impersonation.get('brand')}"
        )

        print(
            f"     Attack   : "
            f"{impersonation.get('attack_type')}"
        )


    # --------------------------------------------------------
    # FAILURE REASONS
    # --------------------------------------------------------

    if status == "FAIL":

        reasons = result.get(
            "reasons",
            []
        )

        if reasons:

            print(
                "     Reasons  : "
                + " | ".join(
                    str(reason)
                    for reason in reasons
                )
            )


    print()


# ============================================================
# TEST SUMMARY
# ============================================================

total = len(TESTS)

accuracy = (
    passed / total
) * 100


print("=" * 80)
print("TEST SUMMARY")
print("=" * 80)

print()

print(
    f"Total tests : {total}"
)

print(
    f"Passed      : {passed}"
)

print(
    f"Failed      : {failed}"
)

print(
    f"Test accuracy: {accuracy:.2f}%"
)

print()


# ============================================================
# FAILED TEST DETAILS
# ============================================================

if failed > 0:

    print("=" * 80)
    print("FAILED TEST DETAILS")
    print("=" * 80)

    print()

    for test in failed_tests:

        print(
            f"Test #{test['number']}: "
            f"{test['name']}"
        )

        print(
            f"URL      : "
            f"{test['url']}"
        )

        print(
            f"Expected : "
            f"{test['expected']}"
        )

        print(
            f"Actual   : "
            f"{test['actual']}"
        )

        reasons = test[
            "result"
        ].get(
            "reasons",
            []
        )

        if reasons:

            print(
                "Reasons  : "
                + " | ".join(
                    str(reason)
                    for reason in reasons
                )
            )

        print()


# ============================================================
# FINAL STATUS
# ============================================================

print("=" * 80)
print("FINAL STATUS")
print("=" * 80)

print()

if failed == 0:

    print(
        "ALL TESTS PASSED!"
    )

else:

    print(
        f"{failed} TEST(S) FAILED."
    )

print()