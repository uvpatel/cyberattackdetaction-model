# IDS Prediction Dashboard - Internship Learning Documentation

An interactive, machine learning-powered **Intrusion Detection System (IDS) Prediction Dashboard** built with Python and Streamlit. This application loads a pre-trained Random Forest model to analyze network flow features, validate logs, run predictions, and map cyberattack classifications to severity levels (Normal vs Alert).

---

## 🛠️ Project Directory Structure

```text
Urvil_Task_IDS_Dashboard/
├── data/
│   └── sample_input.csv         # 105 synthetic network log records for testing
├── docs/
│   └── IDS_Dashboard_Report.pdf # Programmatically generated project report
├── models/
│   ├── best_model.pkl           # Saved RandomForestClassifier model
│   ├── label_encoder.pkl        # Fit LabelEncoder model
│   └── selected_features.txt    # Required feature column list (10 items)
├── outputs/
│   └── sample_output.csv        # Log of predicted rows conforming to requirements
├── screenshots/
│   └── (screenshots of app)     # Dashboard screenshot previews
├── README.md                    # Environment setup & run documentation
├── requirements.txt             # Required python packages
├── app.py                       # Main Streamlit dashboard source code
├── generate_assets.py           # Script to train model & generate mock data
└── generate_report.py           # Script to compile PDF report
```

---

## ⚙️ Local Setup Instructions

Ensure you have **Python 3.8+** installed on your system.

### 1. Initialize Virtual Environment (Recommended)
Isolate your package installations to prevent global system library conflicts:
```bash
# Navigate to the project root folder
cd Urvil_Task_IDS_Dashboard

# Create a virtual environment named 'venv'
python3 -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows (PowerShell):
# .\venv\Scripts\Activate.ps1
```

### 2. Install Dependencies
Install all required libraries specified in `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 3. Generate ML Models and Data (Optional)
The project comes pre-seeded with trained pickle models and data folders. If you want to retrain the classifier or recreate the mock datasets, run:
```bash
python generate_assets.py
```
This generates the Random Forest model, fits the label encoder, registers the 10 selected features, and creates `data/sample_input.csv` for demonstration.

### 4. Run the Streamlit Dashboard
Launch the web interface locally:
```bash
streamlit run app.py
```
The application will automatically open in a new tab in your default web browser (usually at `http://localhost:8501`).

### 5. Compile the PDF Report (Optional)
If you want to regenerate the project documentation PDF, execute:
```bash
python generate_report.py
```
The generated report will be updated at `docs/IDS_Dashboard_Report.pdf`.

---

## 📊 Technical Details & Specifications

### 1. Selected Features List (10 Required Columns)
Your uploaded CSV files **must** contain the following columns (names are case-sensitive):
- `Destination Port`
- `Flow Duration`
- `Total Fwd Packets`
- `Total Backward Packets`
- `Fwd Packet Length Max`
- `Bwd Packet Length Max`
- `Flow Bytes/s`
- `Flow Packets/s`
- `Packet Length Mean`
- `Average Packet Size`

*Note: If extra columns are present in the CSV, the app filters them out automatically. If any required columns are missing, a validation warning lists the missing headers and prevents prediction crashes.*

### 2. Attack Categories & Severity Mappings
- **`BENIGN`** predictions are mapped to **Normal** severity.
- **`DoS`, `Brute Force`, `SQL Injection`, `XSS`, `PortScan`, `Infiltration`** map to **Alert** severity.

### 3. Output CSV Specifications
The downloaded prediction results file contains:
- `record_id`: Row number index starting from 1.
- `predicted_label`: Text string of the attack classification (e.g. DoS, BENIGN).
- `severity`: Classified status (`Normal` or `Alert`).
- `model_name`: Name of the estimator used (`RandomForestClassifier`).
- `prediction_time`: Local timestamp of when predictions were computed.
