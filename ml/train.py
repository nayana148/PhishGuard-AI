import os
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from feature_extractor import extract_features


# ============================================================
# PHISHGUARD ML TRAINING
# ============================================================

print("=" * 70)
print("PHISHGUARD - URL PHISHING DETECTION ML TRAINING")
print("=" * 70)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATASET_FILE = os.path.join(
    BASE_DIR,
    "dataset",
    "phishing_urls_full.csv"
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "model.pkl"
)


# ============================================================
# CHECK DATASET
# ============================================================

if not os.path.exists(DATASET_FILE):

    print("\nERROR:")
    print("Dataset not found:")
    print(DATASET_FILE)

    print(
        "\nRun this first:"
    )

    print(
        "py ml\\download_dataset.py"
    )

    raise SystemExit(1)


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading dataset...")

data = pd.read_csv(
    DATASET_FILE
)

print(
    f"Total rows loaded: {len(data):,}"
)


# ============================================================
# CHECK REQUIRED COLUMNS
# ============================================================

required_columns = [
    "url",
    "label"
]

for column in required_columns:

    if column not in data.columns:

        print(
            f"\nERROR: Missing column: {column}"
        )

        raise SystemExit(1)


# ============================================================
# CLEAN DATA
# ============================================================

print("\nCleaning dataset...")

data = data[
    data["url"].notna()
]

data = data[
    data["label"].notna()
]

data = data[
    data["label"].isin(
        [0, 1]
    )
]

# Remove duplicate URLs

before_duplicates = len(data)

data = data.drop_duplicates(
    subset=["url"]
)

removed_duplicates = (
    before_duplicates
    - len(data)
)

print(
    f"Removed duplicates: "
    f"{removed_duplicates:,}"
)


# ============================================================
# DATASET BALANCE
# ============================================================

legitimate_count = (
    data["label"] == 0
).sum()

phishing_count = (
    data["label"] == 1
).sum()

print("\nDataset distribution:")

print(
    f"Legitimate URLs : "
    f"{legitimate_count:,}"
)

print(
    f"Phishing URLs   : "
    f"{phishing_count:,}"
)

print(
    f"Total URLs      : "
    f"{len(data):,}"
)


# ============================================================
# FEATURE EXTRACTION
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "EXTRACTING URL FEATURES"
)

print(
    "=" * 70
)

X = []
y = []

total = len(data)

for index, row in enumerate(
    data.itertuples(index=False)
):

    url = str(row.url)

    label = int(row.label)

    try:

        # IMPORTANT:
        # Use exactly the same feature
        # extractor used by predict.py.

        feature_vector = extract_features(
            url
        )

        X.append(
            feature_vector
        )

        y.append(
            label
        )

    except Exception as error:

        print(
            f"\nSkipping URL:"
        )

        print(
            url
        )

        print(
            f"Reason: {error}"
        )

    # Progress

    if (
        (index + 1) % 5000 == 0
        or index + 1 == total
    ):

        percentage = (
            (index + 1)
            / total
        ) * 100

        print(
            f"Processed "
            f"{index + 1:,}/"
            f"{total:,} "
            f"({percentage:.1f}%)"
        )


# ============================================================
# CHECK EXTRACTED FEATURES
# ============================================================

if len(X) == 0:

    print(
        "\nERROR: No features were extracted."
    )

    raise SystemExit(1)


feature_count = len(
    X[0]
)

print(
    "\nFeature extraction complete."
)

print(
    f"Usable samples: {len(X):,}"
)

print(
    f"Features per URL: {feature_count}"
)


# ============================================================
# VERIFY FEATURE CONSISTENCY
# ============================================================

print(
    "\nChecking feature consistency..."
)

bad_rows = []

for index, vector in enumerate(X):

    if len(vector) != feature_count:

        bad_rows.append(
            index
        )

if bad_rows:

    print(
        "\nERROR:"
    )

    print(
        "Some URLs produced a different "
        "number of features."
    )

    print(
        f"Bad rows: {len(bad_rows)}"
    )

    raise SystemExit(1)

print(
    "Feature consistency check: PASSED"
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "CREATING TRAIN / TEST DATA"
)

print(
    "=" * 70
)

X_train, X_test, y_train, y_test = (
    train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )
)

print(
    f"Training samples: "
    f"{len(X_train):,}"
)

print(
    f"Testing samples : "
    f"{len(X_test):,}"
)


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "TRAINING RANDOM FOREST"
)

print(
    "=" * 70
)

model = RandomForestClassifier(

    # Number of trees
    n_estimators=300,

    # Let trees learn complex patterns
    max_depth=None,

    # Prevent overly specific splits
    min_samples_split=4,

    # Prevent tiny leaf nodes
    min_samples_leaf=2,

    # Handle class imbalance
    class_weight="balanced",

    # Reproducibility
    random_state=42,

    # Use all CPU cores
    n_jobs=-1
)


model.fit(
    X_train,
    y_train
)

print(
    "\nRandom Forest training complete!"
)


# ============================================================
# PREDICTION
# ============================================================

print(
    "\nEvaluating model..."
)

predictions = model.predict(
    X_test
)


# ============================================================
# PROBABILITIES
# ============================================================

probabilities = model.predict_proba(
    X_test
)


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)


# ============================================================
# DISPLAY PERFORMANCE
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "MODEL PERFORMANCE"
)

print(
    "=" * 70
)

print(
    f"\nAccuracy : "
    f"{accuracy * 100:.2f}%"
)

print(
    f"Precision: "
    f"{precision * 100:.2f}%"
)

print(
    f"Recall   : "
    f"{recall * 100:.2f}%"
)

print(
    f"F1 Score : "
    f"{f1 * 100:.2f}%"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print(
    "\nClassification Report:"
)

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

matrix = confusion_matrix(
    y_test,
    predictions
)

print(
    "Confusion Matrix:"
)

print(
    matrix
)


# ============================================================
# SAVE MODEL
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "SAVING MODEL"
)

print(
    "=" * 70
)

joblib.dump(
    model,
    MODEL_FILE
)

print(
    "\nModel saved successfully!"
)

print(
    f"Location:"
)

print(
    MODEL_FILE
)


# ============================================================
# FINAL INFORMATION
# ============================================================

print(
    "\n" + "=" * 70
)

print(
    "PHISHGUARD TRAINING COMPLETE"
)

print(
    "=" * 70
)

print(
    "\nModel information:"
)

print(
    f"Training samples : "
    f"{len(X_train):,}"
)

print(
    f"Testing samples  : "
    f"{len(X_test):,}"
)

print(
    f"Features         : "
    f"{feature_count}"
)

print(
    f"Accuracy         : "
    f"{accuracy * 100:.2f}%"
)

print(
    f"Precision        : "
    f"{precision * 100:.2f}%"
)

print(
    f"Recall           : "
    f"{recall * 100:.2f}%"
)

print(
    f"F1 Score         : "
    f"{f1 * 100:.2f}%"
)

print(
    "\nModel is ready for testing."
)