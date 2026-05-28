from __future__ import annotations

import argparse
from pathlib import Path
from time import perf_counter

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


DATA_PATH = Path("dataset/cybersecurity_attacks.csv")
TARGET = "Attack Type"
RANDOM_STATE = 42

# These fields are usually created by detection or response systems after an
# attack is identified. Keeping them can inflate validation scores.
LEAKAGE_COLUMNS = {
    "Attack Signature",
    "Action Taken",
    "Severity Level",
    "Alerts/Warnings",
    "IDS/IPS Alerts",
    "Firewall Logs",
}

DROP_HIGH_CARDINALITY_COLUMNS = {
    "Source IP Address",
    "Destination IP Address",
    "User Information",
    "Device Information",
    "Geo-location Data",
    "Proxy Information",
}


def load_data(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    df = pd.read_csv(path)
    if TARGET not in df.columns:
        raise ValueError(f"Target column {TARGET!r} not found. Columns: {list(df.columns)}")

    return df


def add_time_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    timestamp = pd.to_datetime(df.pop("Timestamp"), errors="coerce")
    df["timestamp_year"] = timestamp.dt.year
    df["timestamp_month"] = timestamp.dt.month
    df["timestamp_dayofweek"] = timestamp.dt.dayofweek
    df["timestamp_hour"] = timestamp.dt.hour
    return df


def split_features(df: pd.DataFrame, include_leakage: bool) -> tuple[pd.DataFrame, pd.Series]:
    y = df[TARGET]
    X = df.drop(columns=[TARGET])

    if "Timestamp" in X.columns:
        X = add_time_features(X)

    drop_columns = set(DROP_HIGH_CARDINALITY_COLUMNS)
    if not include_leakage:
        drop_columns |= LEAKAGE_COLUMNS

    X = X.drop(columns=[col for col in drop_columns if col in X.columns])
    return X, y


def make_preprocessor(X: pd.DataFrame) -> ColumnTransformer:
    text_columns = [col for col in ["Payload Data"] if col in X.columns]
    numeric_columns = X.select_dtypes(include=["number"]).columns.tolist()
    categorical_columns = [
        col
        for col in X.columns
        if col not in numeric_columns and col not in text_columns
    ]

    return ColumnTransformer(
        transformers=[
            (
                "numeric",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", StandardScaler()),
                    ]
                ),
                numeric_columns,
            ),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        (
                            "onehot",
                            OneHotEncoder(handle_unknown="ignore", min_frequency=20),
                        ),
                    ]
                ),
                categorical_columns,
            ),
            (
                "payload_text",
                HashingVectorizer(
                    n_features=2**12,
                    alternate_sign=False,
                    ngram_range=(1, 2),
                    lowercase=True,
                ),
                "Payload Data",
            ),
        ],
        remainder="drop",
    )


def benchmark_models(X: pd.DataFrame, y: pd.Series) -> pd.DataFrame:
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    preprocessor = make_preprocessor(X_train)
    models = {
        "majority_baseline": DummyClassifier(strategy="most_frequent"),
        "logistic_regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=250,
            min_samples_leaf=3,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=150,
            learning_rate=0.07,
            random_state=RANDOM_STATE,
        ),
    }

    results = []
    best_name = None
    best_f1 = -1.0
    best_report = ""

    for name, model in models.items():
        steps = []
        if name != "hist_gradient_boosting":
            steps.append(("preprocess", preprocessor))
        else:
            numeric_only = X_train.select_dtypes(include=["number"]).columns.tolist()
            steps.append(
                (
                    "preprocess",
                    ColumnTransformer(
                        transformers=[
                            (
                                "numeric",
                                SimpleImputer(strategy="median"),
                                numeric_only,
                            )
                        ],
                        remainder="drop",
                    ),
                )
            )
        steps.append(("model", model))

        pipeline = Pipeline(steps=steps)
        started = perf_counter()
        pipeline.fit(X_train, y_train)
        elapsed = perf_counter() - started
        predictions = pipeline.predict(X_test)

        macro_f1 = f1_score(y_test, predictions, average="macro")
        results.append(
            {
                "model": name,
                "accuracy": accuracy_score(y_test, predictions),
                "macro_f1": macro_f1,
                "fit_seconds": elapsed,
            }
        )

        if macro_f1 > best_f1:
            best_name = name
            best_f1 = macro_f1
            best_report = classification_report(y_test, predictions)

    print(f"\nBest model: {best_name}")
    print(best_report)
    return pd.DataFrame(results).sort_values("macro_f1", ascending=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark attack type classifiers.")
    parser.add_argument("--data", type=Path, default=DATA_PATH)
    parser.add_argument(
        "--include-leakage",
        action="store_true",
        help="Keep post-detection columns such as signature, action, and severity.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    df = load_data(args.data)

    print(f"Dataset: {args.data}")
    print(f"Shape: {df.shape[0]:,} rows x {df.shape[1]:,} columns")
    print("\nTarget distribution:")
    print(df[TARGET].value_counts().to_string())

    X, y = split_features(df, include_leakage=args.include_leakage)
    print(f"\nFeature columns used ({X.shape[1]}):")
    print(", ".join(X.columns))

    scores = benchmark_models(X, y)
    print("\nBenchmark:")
    print(scores.to_string(index=False, formatters={
        "accuracy": "{:.4f}".format,
        "macro_f1": "{:.4f}".format,
        "fit_seconds": "{:.2f}".format,
    }))


if __name__ == "__main__":
    main()
