import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def build_pdf():
    pdf_path = "docs/IDS_Dashboard_Report.pdf"
    os.makedirs("docs", exist_ok=True)
    
    # Page setup
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    primary_color = colors.HexColor("#1e293b")
    accent_color = colors.HexColor("#6366f1")
    text_color = colors.HexColor("#334155")
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=primary_color,
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=12,
        leading=14,
        textColor=accent_color,
        spaceAfter=20
    )
    
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=text_color,
        spaceAfter=8
    )
    
    bullet_style = ParagraphStyle(
        'BulletCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=text_color,
        leftIndent=20,
        firstLineIndent=-10,
        spaceAfter=4
    )
    
    story = []
    
    # ----------------------------------------------------
    # PAGE 1
    # ----------------------------------------------------
    
    # Title & Subtitle
    story.append(Paragraph("IDS Prediction Dashboard Report", title_style))
    story.append(Paragraph("Internship Learning Documentation & Technical Summary", subtitle_style))
    story.append(Spacer(1, 10))
    
    # Executive Summary
    story.append(Paragraph("1. Executive Summary", heading_style))
    exec_summary_text = (
        "This project outlines the implementation of a local Intrusion Detection System (IDS) Prediction Dashboard "
        "designed to classify network traffic flows and identify potential cyberattack patterns. The system "
        "leverages a machine learning classifier to analyze flow traffic data uploaded in CSV format. Predictions "
        "are labeled by threat type and categorized into severity levels (Normal vs Alert) for administrative review. "
        "The primary goal of this tool is to provide security personnel with a lightweight, reusable, and interactive "
        "interface to analyze logs offline and visual distribution counts of network traffic threats."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 10))
    
    # Machine Learning Model Details
    story.append(Paragraph("2. Classifier Engine Specifications", heading_style))
    model_text = (
        "The machine learning subsystem uses a <b>Random Forest Classifier</b> trained on synthetic network flow logs "
        "designed to mimic standard threat patterns (e.g. CICIDS2017 datasets). The model evaluates logs "
        "against 10 core traffic attributes. Prediction probabilities are output for 7 classes:"
    )
    story.append(Paragraph(model_text, body_style))
    
    story.append(Paragraph("• <b>BENIGN</b>: Standard, harmless system operations.", bullet_style))
    story.append(Paragraph("• <b>DoS (Denial of Service)</b>: Volumetric traffic spikes flooding network links.", bullet_style))
    story.append(Paragraph("• <b>Brute Force</b>: Repetitive credential login attempts flagged on Ports 21/22.", bullet_style))
    story.append(Paragraph("• <b>SQL Injection</b>: Malicious structured queries targeting data entry points.", bullet_style))
    story.append(Paragraph("• <b>XSS (Cross-Site Scripting)</b>: Payload patterns injected via web requests.", bullet_style))
    story.append(Paragraph("• <b>PortScan</b>: Multi-port probes scanning for open target sockets.", bullet_style))
    story.append(Paragraph("• <b>Infiltration</b>: Vulnerability exploits attempting unauthorized host takeovers.", bullet_style))
    story.append(Spacer(1, 10))
    
    # Severity Policy
    story.append(Paragraph("3. Severity Mapping Policy", heading_style))
    severity_text = (
        "The dashboard translates categorical predictions into risk profiles to highlight items requiring immediate triage:"
    )
    story.append(Paragraph(severity_text, body_style))
    
    policy_data = [
        ["Predicted Label", "Mapped Severity", "Administrative Action"],
        ["BENIGN", "Normal", "None. Logged for standard record maintenance."],
        ["DoS / Brute Force", "Alert", "Immediate threat mitigation. Check traffic rate limit and firewall rules."],
        ["SQL Injection / XSS", "Alert", "App vulnerability triage. Inspect web app input sanitizers."],
        ["PortScan / Infiltration", "Alert", "System audit. Investigate host integrity and restrict open ports."]
    ]
    
    policy_table = Table(policy_data, colWidths=[1.8 * inch, 1.3 * inch, 3.4 * inch])
    policy_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('TEXTCOLOR', (0,0), (-1,0), primary_color),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,1), (-1,-1), 9),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(policy_table)
    
    story.append(PageBreak())
    
    # ----------------------------------------------------
    # PAGE 2
    # ----------------------------------------------------
    
    # Selected Features list
    story.append(Paragraph("4. Input Feature Requirements", heading_style))
    feat_text = (
        "The IDS Dashboard validates uploaded files to ensure they conform to the features used in model training. "
        "The table below defines the 10 selected network metrics required in the CSV uploader:"
    )
    story.append(Paragraph(feat_text, body_style))
    
    feature_data = [
        ["Feature Name", "Data Type", "Description / Significance"],
        ["Destination Port", "Integer", "Target socket identifier (determines application channel)."],
        ["Flow Duration", "Float", "Total duration of the network connection stream (microseconds)."],
        ["Total Fwd Packets", "Integer", "Total count of packets sent in the forward direction."],
        ["Total Backward Packets", "Integer", "Total count of packets sent in the backward direction."],
        ["Fwd Packet Length Max", "Float", "Maximum length of forward packets in bytes."],
        ["Bwd Packet Length Max", "Float", "Maximum length of backward packets in bytes."],
        ["Flow Bytes/s", "Float", "Rate of byte transmission per second."],
        ["Flow Packets/s", "Float", "Rate of packet transmissions per second."],
        ["Packet Length Mean", "Float", "Average size of packets transmitted in the stream."],
        ["Average Packet Size", "Float", "Mean packet size adjusted for directional headers."]
    ]
    
    feature_table = Table(feature_data, colWidths=[1.8 * inch, 1.2 * inch, 3.5 * inch])
    feature_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('TEXTCOLOR', (0,0), (-1,0), primary_color),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,1), (-1,-1), 8.5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(feature_table)
    story.append(Spacer(1, 10))
    
    # Dashboard Architecture & Usability
    story.append(Paragraph("5. Dashboard Capabilities & Usability", heading_style))
    capabilities_text = (
        "The interface was designed in Streamlit for optimal local deployment, responsiveness, and clear presentation. "
        "It provides safety layers and clear user prompts:"
    )
    story.append(Paragraph(capabilities_text, body_style))
    
    story.append(Paragraph("• <b>Validation Engine</b>: Ensures uploaded data contains all 10 feature headers. Displays descriptive errors detailing exactly what is missing without crashing.", bullet_style))
    story.append(Paragraph("• <b>Summary Indicators</b>: Displays critical aggregate metrics (Total Logs, Normal Count, Attack Count, Top Attack Type) in styled glassmorphic widgets.", bullet_style))
    story.append(Paragraph("• <b>Interactive Data Plotting</b>: Utilizes Plotly components to display class ratios, normal-to-alert proportions, and multidimensional cluster scatter plots.", bullet_style))
    story.append(Paragraph("• <b>Structured Downloads</b>: Outputs a clean file mapping row IDs to predictions, severities, and timestamps conforming strictly to project submission requirements.", bullet_style))
    story.append(Spacer(1, 10))
    
    # Setup Instructions
    story.append(Paragraph("6. Project Setup Summary", heading_style))
    setup_text = (
        "To run the dashboard locally, unzip the project folder and run the following in your terminal:<br/>"
        "<code>pip install -r requirements.txt</code><br/>"
        "<code>python generate_assets.py</code> (Optional: regenerates the ML models and data)<br/>"
        "<code>streamlit run app.py</code>"
    )
    story.append(Paragraph(setup_text, body_style))
    
    doc.build(story)
    print(f"Report compiled successfully at {pdf_path}")

if __name__ == "__main__":
    build_pdf()
