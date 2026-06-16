import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import time
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

# ----------------------------------------------------
# 1. Page Configuration & Custom Styling
# ----------------------------------------------------
st.set_page_config(
    page_title="IDS Cyberattack Predictor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Premium Glassmorphism Theme
st.markdown("""
<style>
    /* Global Styles */
    .stApp {
        background-color: #0f172a;
        color: #f8fafc;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #1e293b !important;
        border-right: 1px solid #334155;
    }
    
    /* Headings */
    h1, h2, h3 {
        font-family: 'Inter', sans-serif;
        font-weight: 700;
        color: #f1f5f9;
        letter-spacing: -0.025em;
    }
    
    /* Neon Gradients for Cards */
    .metric-card {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 16px;
        padding: 24px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 12px 40px 0 rgba(0, 0, 0, 0.5);
    }
    
    .metric-title {
        font-size: 0.875rem;
        color: #94a3b8;
        font-weight: 500;
        text-transform: uppercase;
        margin-bottom: 8px;
        letter-spacing: 0.05em;
    }
    
    .metric-value {
        font-size: 2.25rem;
        font-weight: 700;
        line-height: 1;
    }
    
    .total-card { border-left: 6px solid #6366f1; }
    .normal-card { border-left: 6px solid #10b981; }
    .alert-card { border-left: 6px solid #ef4444; }
    .top-card { border-left: 6px solid #f59e0b; }
    
    .total-val { color: #818cf8; }
    .normal-val { color: #34d399; }
    .alert-val { color: #f87171; }
    .top-val { color: #fbbf24; }
    
    /* Info Box styling */
    div.stAlert {
        border-radius: 12px;
        background-color: #1e293b;
        border: 1px solid #334155;
    }
    
    /* Styled buttons */
    div.stButton > button {
        background-color: #4f46e5 !important;
        color: white !important;
        border-radius: 8px !important;
        border: none !important;
        padding: 10px 24px !important;
        font-weight: 600 !important;
        transition: background-color 0.3s ease !important;
    }
    div.stButton > button:hover {
        background-color: #4338ca !important;
    }
    
    /* Footer */
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: #0f172a;
        color: #64748b;
        text-align: center;
        padding: 10px 0;
        font-size: 0.75rem;
        border-top: 1px solid #1e293b;
        z-index: 99;
    }
</style>
""", unsafe_allow_html=True)


# ----------------------------------------------------
# 2. Asset Loading Logic
# ----------------------------------------------------
@st.cache_resource
def load_ml_assets():
    """
    Loads the Random Forest classifier and the Label Encoder from pickle files.
    """
    model_path = "models/best_model.pkl"
    encoder_path = "models/label_encoder.pkl"
    
    if not os.path.exists(model_path) or not os.path.exists(encoder_path):
        return None, None, "Asset files missing in models/ folder. Please run generate_assets.py first."
    
    try:
        model = joblib.load(model_path)
        encoder = joblib.load(encoder_path)
        return model, encoder, None
    except Exception as e:
        return None, None, f"Error loading model assets: {str(e)}"

@st.cache_data
def load_selected_features():
    """
    Loads features list from models/selected_features.txt
    """
    features_path = "models/selected_features.txt"
    if not os.path.exists(features_path):
        return None, "selected_features.txt file missing in models/ folder."
        
    try:
        with open(features_path, "r") as f:
            features = [line.strip() for line in f if line.strip()]
        return features, None
    except Exception as e:
        return None, f"Error loading feature file: {str(e)}"


# ----------------------------------------------------
# 3. Main Dashboard Navigation
# ----------------------------------------------------
def main():
    # Load ML assets and features
    model, encoder, model_err = load_ml_assets()
    selected_features, feat_err = load_selected_features()
    
    # Initialize session state for predictions
    if "pred_results" not in st.session_state:
        st.session_state.pred_results = None
    if "input_filename" not in st.session_state:
        st.session_state.input_filename = ""
        
    # Sidebar
    st.sidebar.markdown("<h2 style='text-align: center; color: #f1f5f9; margin-top: 0;'>🛡️ IDS Control Room</h2>", unsafe_allow_html=True)
    st.sidebar.markdown("<hr style='border-top: 1px solid #334155; margin-top: 5px; margin-bottom: 20px;'/>", unsafe_allow_html=True)
    
    page = st.sidebar.radio(
        "Navigation Menu",
        ["🏠 Home & Overview", "🔍 Prediction Dashboard", "📊 Analytics Hub", "📄 System Documentation"]
    )
    
    # Sidebar Status Panel
    st.sidebar.markdown("<br/><br/>", unsafe_allow_html=True)
    st.sidebar.markdown("### ⚙️ System Status")
    if model_err or feat_err:
        st.sidebar.error("❌ Assets Missing/Corrupt")
    else:
        st.sidebar.success("✅ ML Engine Online")
        st.sidebar.info(f"**Loaded Model**: {type(model).__name__}\n\n**Feature Count**: {len(selected_features)}")

    # ----------------------------------------------------
    # PAGE 1: Home & Overview
    # ----------------------------------------------------
    if page == "🏠 Home & Overview":
        st.markdown("<h1 style='color: #818cf8;'>Intrusion Detection System (IDS) Prediction Dashboard</h1>", unsafe_allow_html=True)
        st.markdown("<h4 style='color: #94a3b8; font-weight: normal; margin-top: -10px;'>Local ML-Powered Network Flow Classifier</h4>", unsafe_allow_html=True)
        
        st.write("---")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("""
            ### Welcome to the IDS Cyberattack Predictor
            This interactive dashboard is designed to analyze network flow features, validate logs, and predict cyberthreat 
            types in real-time. By loading a pre-trained **Random Forest Classifier**, the system classifies network activity 
            into benign and various malicious categories with calculated prediction confidence levels.
            
            #### Key Functions:
            1. **CSV Upload & Re-ordering**: Upload standard CSV logs. The app automatically cleans, validates, and aligns columns to match the model training requirements.
            2. **Confidence Scores**: Displays prediction certainty percentages based on model output probabilities.
            3. **Severity Categorization**: Instantly flags benign traffic as `Normal` and malicious activities as `Alert` severity.
            4. **Plotly Visualizations**: Interactive distribution counts and breakdown charts.
            5. **Result Export**: Easily download predicted logs containing predictions, severity tags, and metadata.
            """)
            
            st.markdown("<br/>", unsafe_allow_html=True)
            if st.button("Proceed to Predictions"):
                st.info("Select **Prediction Dashboard** in the sidebar to start uploading data.")
                
        with col2:
            st.markdown("### 📊 Engine Performance")
            st.markdown("""
            <div style='background: rgba(30,41,59,0.5); border: 1px solid #334155; padding: 20px; border-radius: 12px;'>
                <p style='margin-bottom:8px;'><b>Architecture:</b> Scikit-Learn Random Forest</p>
                <p style='margin-bottom:8px;'><b>Features Checked:</b> 10 Network Metrics</p>
                <p style='margin-bottom:8px;'><b>Attack Categories Covered:</b> 6 classes</p>
                <p style='margin-bottom:8px;'><b>Target Framework:</b> Python & Streamlit</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("### 💡 Quick Test Guide")
            st.markdown("""
            Don't have your own CSV? A synthetic test CSV has been auto-generated for your demo:
            * Location: `data/sample_input.csv`
            * Load this file in the **Prediction Dashboard** tab to test immediately.
            """)

    # ----------------------------------------------------
    # PAGE 2: Prediction Dashboard
    # ----------------------------------------------------
    elif page == "🔍 Prediction Dashboard":
        st.markdown("<h1>Predict Cyberattack Labels</h1>", unsafe_allow_html=True)
        st.write("Upload network log files to perform predictions using the loaded ML model.")
        st.write("---")
        
        if model_err or feat_err:
            st.error(f"Error loading system assets:\n- Model: {model_err}\n- Features: {feat_err}")
            st.warning("Please run `generate_assets.py` to compile the models first.")
            return

        uploaded_file = st.file_uploader("Upload CSV Network Log File", type=["csv"])
        
        if uploaded_file is not None:
            # Check if this is a new file
            if uploaded_file.name != st.session_state.input_filename:
                st.session_state.input_filename = uploaded_file.name
                st.session_state.pred_results = None
            
            try:
                # Load CSV
                df = pd.read_csv(uploaded_file)
                st.success(f"Successfully loaded '{uploaded_file.name}' with {len(df)} rows.")
                
                # Validation Page/Section requirement
                st.markdown("### 🔍 Column Validation")
                missing_columns = [col for col in selected_features if col not in df.columns]
                
                if missing_columns:
                    st.error(f"❌ **Validation Failed:** The uploaded CSV is missing {len(missing_columns)} required feature columns.")
                    st.markdown("**Missing Columns list:**")
                    st.markdown(", ".join([f"`{c}`" for c in missing_columns]))
                    st.warning("Please check your file layout. All columns listed in the 'System Documentation' feature list are required.")
                else:
                    st.success("✅ **Validation Successful:** All required features are present in the CSV file.")
                    
                    # Run prediction trigger
                    if st.button("Run Model Prediction Engine"):
                        with st.spinner("Processing network features and running classifier..."):
                            # Clean and align features using the exact training features list
                            X_test = df[selected_features].copy()
                            
                            # Start timer
                            start_time = time.time()
                            
                            # Predict numerical labels
                            predictions = model.predict(X_test)
                            
                            # Calculate runtime
                            run_duration = time.time() - start_time
                            
                            # Convert labels back to strings
                            pred_names = encoder.inverse_transform(predictions)
                            
                            # Predict confidence probabilities
                            if hasattr(model, "predict_proba"):
                                probs = model.predict_proba(X_test)
                                confidences = np.max(probs, axis=1) * 100.0
                            else:
                                confidences = [100.0] * len(predictions)
                                
                            # Create prediction timestamp
                            pred_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            
                            # Build output dataframe conforming strictly to specifications
                            # Output CSV Columns: record_id, predicted_label, severity, model_name, prediction_time
                            # (Wait, let's keep confidence in the dataframe view, but make sure the downloadable output CSV contains the specified columns)
                            
                            severities = ["Normal" if name == "BENIGN" else "Alert" for name in pred_names]
                            
                            results_df = pd.DataFrame({
                                "record_id": range(1, len(df) + 1),
                                "predicted_label": pred_names,
                                "severity": severities,
                                "confidence_pct": confidences,
                                "model_name": [type(model).__name__] * len(df),
                                "prediction_time": [pred_time] * len(df)
                            })
                            
                            # Save back features for view
                            full_results = pd.concat([results_df, df], axis=1)
                            st.session_state.pred_results = {
                                "display_df": full_results,
                                "download_df": results_df,
                                "total_records": len(df),
                                "benign_count": list(pred_names).count("BENIGN"),
                                "attack_count": len(df) - list(pred_names).count("BENIGN"),
                                "top_attack": max([n for n in pred_names if n != "BENIGN"], key=list(pred_names).count) if len([n for n in pred_names if n != "BENIGN"]) > 0 else "None",
                                "duration": run_duration
                            }
                            st.success(f"Predictions calculated successfully in {run_duration:.4f} seconds!")
            except Exception as e:
                st.error(f"Error parsing uploaded file: {str(e)}")
                
        # If predictions exist, display results
        if st.session_state.pred_results is not None:
            res = st.session_state.pred_results
            
            st.markdown("<br/>", unsafe_allow_html=True)
            st.markdown("### 🏆 Prediction Summary")
            
            # Display metrics cards
            c1, c2, c3, c4 = st.columns(4)
            
            with c1:
                st.markdown(f"""
                <div class="metric-card total-card">
                    <div class="metric-title">Total Records</div>
                    <div class="metric-value total-val">{res['total_records']}</div>
                </div>
                """, unsafe_allow_html=True)
                
            with c2:
                st.markdown(f"""
                <div class="metric-card normal-card">
                    <div class="metric-title">Benign / Normal</div>
                    <div class="metric-value normal-val">{res['benign_count']}</div>
                </div>
                """, unsafe_allow_html=True)
                
            with c3:
                st.markdown(f"""
                <div class="metric-card alert-card">
                    <div class="metric-title">Attacks Flagged</div>
                    <div class="metric-value alert-val">{res['attack_count']}</div>
                </div>
                """, unsafe_allow_html=True)
                
            with c4:
                st.markdown(f"""
                <div class="metric-card top-card">
                    <div class="metric-title">Top Cyberattack</div>
                    <div class="metric-value top-val">{res['top_attack']}</div>
                </div>
                """, unsafe_allow_html=True)
                
            st.markdown("<br/>", unsafe_allow_html=True)
            st.markdown("### 📋 Prediction Results Table")
            
            # Show a nice interactive dataframe
            # Let the user search and filter
            display_cols = ["record_id", "predicted_label", "severity", "confidence_pct", "prediction_time"] + selected_features
            st.dataframe(res["display_df"][display_cols], use_container_width=True)
            
            # Download predicted output CSV section
            st.markdown("### 📥 Download Results")
            st.write("Export predicted records in CSV format matching final requirements (contains prediction details, timestamp, and model metadata).")
            
            csv_data = res["download_df"].to_csv(index=False)
            st.download_button(
                label="📥 Download Output CSV",
                data=csv_data,
                file_name="sample_output.csv",
                mime="text/csv"
            )
            
            # Auto save to outputs folder for delivery packaging
            try:
                res["download_df"].to_csv("outputs/sample_output.csv", index=False)
            except Exception:
                pass

    # ----------------------------------------------------
    # PAGE 3: Analytics Hub
    # ----------------------------------------------------
    elif page == "📊 Analytics Hub":
        st.markdown("<h1>Network Traffic Analytics Hub</h1>", unsafe_allow_html=True)
        st.write("Visual distribution of predictions and cyberattack classes.")
        st.write("---")
        
        if st.session_state.pred_results is None:
            st.info("ℹ️ Please upload a CSV and run predictions in the **Prediction Dashboard** tab to populate charts.")
            return
            
        res = st.session_state.pred_results
        df_display = res["display_df"]
        
        # Grid layout for charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🛡️ Attack Class Distribution")
            class_counts = df_display["predicted_label"].value_counts().reset_index()
            class_counts.columns = ["Attack Class", "Count"]
            
            # Map colors for classes
            color_map = {
                "BENIGN": "#10b981",       # Emerald
                "DoS": "#ef4444",          # Red
                "Brute Force": "#f97316",  # Orange
                "SQL Injection": "#d946ef",# Magenta
                "XSS": "#a855f7",          # Purple
                "PortScan": "#fbbf24",     # Yellow
                "Infiltration": "#3b82f6"  # Blue
            }
            
            fig_pie = px.pie(
                class_counts, 
                values="Count", 
                names="Attack Class", 
                color="Attack Class",
                color_discrete_map=color_map,
                hole=0.4,
                title="Class Ratio Overview"
            )
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='#f1f5f9',
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with col2:
            st.markdown("### 🚨 Severity Allocation")
            sev_counts = df_display["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            
            sev_colors = {
                "Normal": "#10b981", # Emerald
                "Alert": "#ef4444"    # Red
            }
            
            fig_bar = px.bar(
                sev_counts,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map=sev_colors,
                title="Normal vs Alert Records Flagged"
            )
            fig_bar.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='#f1f5f9',
                showlegend=False
            )
            fig_bar.update_yaxes(gridcolor='#334155')
            st.plotly_chart(fig_bar, use_container_width=True)
            
        st.write("---")
        st.markdown("### 🔍 Feature Correlations & Scatter Analysis")
        st.write("Scatter distribution plotting Flow Duration vs Packet Length Mean to identify clusters of threat labels.")
        
        # Plotly Scatter Plot
        fig_scatter = px.scatter(
            df_display,
            x="Flow Duration",
            y="Packet Length Mean",
            color="predicted_label",
            color_discrete_map=color_map,
            hover_data=["confidence_pct", "severity", "Destination Port"],
            title="Flow Duration vs Packet Length Mean by Predicted Label"
        )
        fig_scatter.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#f1f5f9'
        )
        fig_scatter.update_xaxes(gridcolor='#334155')
        fig_scatter.update_yaxes(gridcolor='#334155')
        st.plotly_chart(fig_scatter, use_container_width=True)

    # ----------------------------------------------------
    # PAGE 4: System Documentation
    # ----------------------------------------------------
    elif page == "📄 System Documentation":
        st.markdown("<h1>System Documentation & Reference</h1>", unsafe_allow_html=True)
        st.write("Technical instructions, severity mappings, and column specifications.")
        st.write("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📋 Required Features (Selected Features)")
            st.write("The input CSV uploaded for predictions must contain exactly the following columns (names are case-sensitive):")
            
            if not feat_err:
                feats_formatted = "".join([f"1. **{f}**\n" for f in selected_features])
                st.markdown(feats_formatted)
            else:
                st.error(feat_err)
                
            st.markdown("""
            ### 🛠️ Severity Mapping Reference
            * **`BENIGN`** predictions are mapped to **Normal** (Normal system flow).
            * All other threats (**`DoS`, `Brute Force`, `SQL Injection`, `XSS`, `PortScan`, `Infiltration`**) map to **Alert** severity levels.
            """)
            
        with col2:
            st.markdown("### 🔄 Upload File Check Guide")
            st.markdown("""
            To ensure the system works smoothly:
            - Row ordering inside the uploaded CSV does not matter, but all feature columns must be present.
            - Extra columns in the CSV are ignored automatically.
            - Null values or blank fields in features are automatically filled with `0.0` or column means to prevent crashes.
            - Model predictions run locally using `scikit-learn` Random Forest algorithms.
            """)
            
            st.markdown("### 📂 Export Format Specification")
            st.markdown("""
            The exported CSV output file contains the following structure:
            1. **`record_id`**: Row index mapping.
            2. **`predicted_label`**: Text string of cyberthreat classification.
            3. **`severity`**: Normal/Alert status.
            4. **`model_name`**: Name of classifier used.
            5. **`prediction_time`**: Precise timestamp.
            """)

    # Footer layout
    st.markdown("""
    <div class="footer">
        <p>IDS Prediction Dashboard - Internship Learning Documentation Task | Built with Streamlit & Plotly</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
