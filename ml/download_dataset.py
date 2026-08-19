import os
import pandas as pd
from ucimlrepo import fetch_ucirepo


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATASET_DIR = os.path.join(
    BASE_DIR,
    "dataset"
)

os.makedirs(
    DATASET_DIR,
    exist_ok=True
)


# ============================================================
# DOWNLOAD UCI DATASET
# ============================================================

print("=" * 60)
print("PhishGuard - Downloading PhiUSIIL Dataset")
print("=" * 60)

print("\nConnecting to UCI...")

dataset = fetch_ucirepo(
    id=967
)

print("Dataset downloaded successfully!")


# ============================================================
# GET DATA
# ============================================================

X = dataset.data.features.copy()
y = dataset.data.targets.copy()


print(
    f"\nTotal records: {len(X)}"
)

print(
    f"Features available: {len(X.columns)}"
)


# ============================================================
# FIND URL COLUMN
# ============================================================

url_column = None

for column in X.columns:

    if column.lower() == "url":

        url_column = column
        break


if url_column is None:

    raise ValueError(
        "URL column was not found in the dataset."
    )


# ============================================================
# FIND LABEL COLUMN
# ============================================================

label_column = None

for column in y.columns:

    if column.lower() == "label":

        label_column = column
        break


if label_column is None:

    # Use first target column
    label_column = y.columns[0]


# ============================================================
# BUILD CLEAN DATASET
# ============================================================

data = pd.DataFrame()

data["url"] = X[url_column].astype(str)

data["original_label"] = y[label_column]


# ============================================================
# UCI LABEL FORMAT
#
# UCI:
# 1 = legitimate
# 0 = phishing
#
# Our project:
# 0 = legitimate
# 1 = phishing
# ============================================================

data["label"] = (
    data["original_label"]
    .astype(int)
    .map({
        1: 0,
        0: 1
    })
)


# ============================================================
# REMOVE INVALID ROWS
# ============================================================

data = data[
    data["url"].notna()
]

data = data[
    data["label"].notna()
]


# ============================================================
# REMOVE DUPLICATES
# ============================================================

before = len(data)

data = data.drop_duplicates(
    subset=["url"]
)

after = len(data)

print(
    f"\nRemoved duplicates: "
    f"{before - after}"
)


# ============================================================
# SAVE COMPLETE DATASET
# ============================================================

full_dataset_file = os.path.join(
    DATASET_DIR,
    "phishing_urls_full.csv"
)

data[
    ["url", "label"]
].to_csv(
    full_dataset_file,
    index=False
)


# ============================================================
# SPLIT LEGITIMATE / PHISHING
# ============================================================

legitimate = data[
    data["label"] == 0
][["url", "label"]]

phishing = data[
    data["label"] == 1
][["url", "label"]]


legitimate_file = os.path.join(
    DATASET_DIR,
    "legitimate_large.csv"
)

phishing_file = os.path.join(
    DATASET_DIR,
    "phishing_large.csv"
)


legitimate.to_csv(
    legitimate_file,
    index=False
)

phishing.to_csv(
    phishing_file,
    index=False
)


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("DATASET READY")
print("=" * 60)

print(
    f"\nTotal URLs: {len(data)}"
)

print(
    f"Legitimate: {len(legitimate)}"
)

print(
    f"Phishing:   {len(phishing)}"
)

print(
    f"\nSaved:"
)

print(
    f"  {full_dataset_file}"
)

print(
    f"  {legitimate_file}"
)

print(
    f"  {phishing_file}"
)

print("\nDone!")