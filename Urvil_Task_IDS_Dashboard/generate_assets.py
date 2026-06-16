import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

def main():
    print("Starting ML asset generation...")
    
    # 1. Define Selected Features list
    # These represent typical features found in network flow traffic (e.g., CICIDS2017)
    selected_features = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Fwd Packet Length Max",
        "Bwd Packet Length Max",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Packet Length Mean",
        "Average Packet Size"
    ]
    
    # Ensure directories exist
    os.makedirs("models", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    os.makedirs("outputs", exist_ok=True)
    
    # Write feature list to selected_features.txt
    features_path = "models/selected_features.txt"
    with open(features_path, "w") as f:
        for feat in selected_features:
            f.write(feat + "\n")
    print(f"Created {features_path}")
    
    # 2. Generate Synthetic Dataset
    np.random.seed(42)
    n_samples = 1500
    
    # Define attack classes
    classes = ["BENIGN", "DoS", "Brute Force", "SQL Injection", "XSS", "PortScan", "Infiltration"]
    
    # Create empty dataframe for features
    data = pd.DataFrame(index=range(n_samples))
    
    # Generate labels first so we can make feature distributions class-dependent
    labels = np.random.choice(classes, size=n_samples, p=[0.60, 0.15, 0.08, 0.04, 0.03, 0.07, 0.03])
    data["Label"] = labels
    
    # destination port: BENIGN is usually 80/443, DoS/SQLi/XSS also 80/443, Brute Force is 22/21, PortScan is random
    ports = []
    for lbl in labels:
        if lbl in ["BENIGN", "SQL Injection", "XSS"]:
            ports.append(np.random.choice([80, 443, 8080]))
        elif lbl == "Brute Force":
            ports.append(np.random.choice([21, 22]))
        elif lbl == "DoS":
            ports.append(np.random.choice([80, 443]))
        elif lbl == "PortScan":
            ports.append(np.random.randint(1024, 65535))
        else: # Infiltration
            ports.append(np.random.choice([135, 445, 3389]))
    data["Destination Port"] = ports
    
    # Flow Duration (microseconds) - Attacks like DoS or Infiltration can have very high/low flow duration
    durations = []
    for lbl in labels:
        if lbl == "BENIGN":
            durations.append(np.random.exponential(10000) + 100)
        elif lbl == "DoS":
            durations.append(np.random.exponential(500000) + 10000)
        elif lbl == "PortScan":
            durations.append(np.random.exponential(1000) + 10)
        else:
            durations.append(np.random.exponential(100000) + 500)
    data["Flow Duration"] = durations
    
    # Packets counts
    data["Total Fwd Packets"] = data["Label"].apply(
        lambda l: np.random.randint(1, 15) if l == "BENIGN" else (np.random.randint(10, 200) if l == "DoS" else np.random.randint(2, 50))
    )
    data["Total Backward Packets"] = data["Label"].apply(
        lambda l: np.random.randint(0, 15) if l == "BENIGN" else (np.random.randint(5, 150) if l == "DoS" else np.random.randint(1, 40))
    )
    
    # Packet lengths
    data["Fwd Packet Length Max"] = data["Label"].apply(
        lambda l: np.random.randint(20, 1500) if l in ["SQL Injection", "XSS"] else (np.random.randint(40, 1000) if l == "BENIGN" else np.random.randint(0, 500))
    )
    data["Bwd Packet Length Max"] = data["Label"].apply(
        lambda l: np.random.randint(40, 1500) if l in ["SQL Injection", "XSS"] else (np.random.randint(40, 1000) if l == "BENIGN" else np.random.randint(0, 500))
    )
    
    # Calculations based on duration and packets
    # Avoid division by zero
    data["Flow Bytes/s"] = ((data["Fwd Packet Length Max"] + data["Bwd Packet Length Max"]) * data["Total Fwd Packets"]) / (data["Flow Duration"] / 1e6 + 1e-5)
    data["Flow Packets/s"] = (data["Total Fwd Packets"] + data["Total Backward Packets"]) / (data["Flow Duration"] / 1e6 + 1e-5)
    
    # General packet size indicators
    data["Packet Length Mean"] = (data["Fwd Packet Length Max"] + data["Bwd Packet Length Max"]) / 2.0
    data["Average Packet Size"] = data["Packet Length Mean"] * 1.1 + np.random.normal(0, 10, n_samples)
    data["Average Packet Size"] = data["Average Packet Size"].clip(lower=0)
    
    # Clean up infinite values and NaNs
    data = data.replace([np.inf, -np.inf], 0.0)
    data = data.fillna(0.0)
    
    # Separate features and target
    X = data[selected_features]
    y = data["Label"]
    
    # 3. Label Encoding
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Save LabelEncoder
    encoder_path = "models/label_encoder.pkl"
    joblib.dump(le, encoder_path)
    print(f"Saved label encoder to {encoder_path}")
    
    # 4. Model Training
    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    clf.fit(X, y_encoded)
    
    # Save Model
    model_path = "models/best_model.pkl"
    joblib.dump(clf, model_path)
    print(f"Saved trained Random Forest model to {model_path}")
    
    # Verify classes mapped
    for idx, class_name in enumerate(le.classes_):
        print(f"Class {idx} -> {class_name}")
        
    # 5. Export sample input CSV (without the label column)
    # We will generate a distinct set of samples for testing (120 records, balanced across classes for better dashboard demo)
    sample_records = []
    for target_lbl in classes:
        sub_df = data[data["Label"] == target_lbl]
        # sample 15 records per class if possible, else sample with replacement
        sample_records.append(sub_df.sample(n=15, replace=True, random_state=42))
        
    sample_df = pd.concat(sample_records).sample(frac=1, random_state=123).reset_index(drop=True)
    
    # Keep target column in a separate mapping or file just in case, but sample uploader inputs MUST match features
    sample_input = sample_df[selected_features].copy()
    
    # Add a bit of noise to sample inputs so they aren't exactly identical to training
    for col in selected_features:
        if col != "Destination Port":
            noise = np.random.normal(0, sample_input[col].std() * 0.05, len(sample_input))
            sample_input[col] = (sample_input[col] + noise).clip(lower=0)
            if sample_input[col].dtype in [np.int64, np.int32]:
                sample_input[col] = sample_input[col].round().astype(int)
    
    sample_input_path = "data/sample_input.csv"
    sample_input.to_csv(sample_input_path, index=False)
    print(f"Created sample input CSV at {sample_input_path} with {len(sample_input)} rows.")
    
    print("Asset generation complete!")

if __name__ == "__main__":
    main()
