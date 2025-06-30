import re
import streamlit as st
import pandas as pd
import json
from datetime import datetime
from collections import deque, Counter
from io import StringIO, BytesIO
import pdfkit  # For PDF export
from jinja2 import Environment, FileSystemLoader, select_autoescape

# --- Constants ---
SUSPICIOUS_RULES = {
    "Shadow Copy + Process Kill": [
        r"vssadmin\s+create\s+shadow",
        r"(taskkill|process deleted)"
    ],
    "User Escalation": [
        r"net localgroup administrators",
        r"runas"
    ],
    "Unexpected File Deletion": [
        r"deleted.*\.(log|bak|shadow)",
        r"file.*deleted.*(system32|windows)"
    ],
    "Unusual Port Usage": [
        r"port=(6[0-5]{1}[0-5]{2}[0-9]{1}|4915[2-9]|491[6-9][0-9]|49[2-9][0-9]{2}|[5-9][0-9]{4})"
    ],
    "Persistence Behavior": [
        r"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ],
    "Security Tools Disabled": [
        r"(defender off|AV disabled|firewall disable)"
    ],
    "Exfiltration Suspicion": [
        r"(zip|compressed).*external IP",
        r"(upload|transferred).*http[s]?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3})(?::[0-9]+)?"
    ],
    "Unusual Login Time": [],
    "Multiple Failed Logins": []
}

# --- Jinja2 Template Setup for HTML/PDF Reports ---
try:
    env = Environment(
        loader=FileSystemLoader("."),  # looks in current directory
        autoescape=select_autoescape()
    )
    template = env.get_template("report_template.html")
except:
    template = None

# Fallback template if not external
DEFAULT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Log Anomaly Report</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        h1 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1>🛡️ Corporate Log Anomaly Detection Report</h1>
    <h2>Flagged Anomalies</h2>
    {{ table }}
    <h2>Anomaly Statistics</h2>
    {{ chart }}
</body>
</html>
"""

# --- Helper Functions ---
def parse_timestamp(text):
    """Try multiple timestamp formats"""
    for fmt in ('%Y-%m-%d %H:%M:%S', '%b %d %H:%M:%S', '%Y/%m/%d %H:%M', '%a %b %d %H:%M:%S %Y'):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None

def extract_log_fields(line):
    """Extract structured fields from log line"""
    try:
        # Basic field extraction
        timestamp_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
        if not timestamp_match:
            timestamp_match = re.search(r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line)

        actor_match = re.search(r'user=([^\s]+)', line) or re.search(r'actor=([^\s]+)', line)
        process_match = re.search(r'proc=([^\s]+)', line)
        action_match = re.search(r'action=([^\s]+)', line)
        target_match = re.search(r'target=([^\s]+)', line)
        event_type_match = re.search(r'type=([^\s]+)', line)

        return {
            'timestamp': parse_timestamp(timestamp_match.group()) if timestamp_match else None,
            'actor': actor_match.group(1) if actor_match else None,
            'action': action_match.group(1).lower() if action_match else None,
            'target': target_match.group(1) if target_match else None,
            'process': process_match.group(1) if process_match else None,
            'event_type': event_type_match.group(1) if event_type_match else None,
            'raw': line.strip()
        }
    except Exception:
        return {'raw': line.strip(), 'error': True}

def detect_suspicious_activity(log_df):
    """Detect suspicious patterns in the logs"""
    anomalies = []

    # Rule 1: Shadow Copy + Process Kill
    shadow_queue = deque(maxlen=10)
    for _, row in log_df.iterrows():
        line = row['raw'].lower()
        if any(re.search(pattern, line) for pattern in SUSPICIOUS_RULES["Shadow Copy + Process Kill"]):
            shadow_queue.append(row)
            if len(shadow_queue) >= 2 and any(
                re.search(SUSPICIOUS_RULES["Shadow Copy + Process Kill"][1], r.raw.lower())
                for r in shadow_queue
            ):
                anomalies.append({
                    "timestamp": row['timestamp'],
                    "actor": row['actor'],
                    "action": row['action'],
                    "target": row['target'],
                    "rule": "Shadow Copy + Process Kill",
                    "reason": "Detected vssadmin shadow copy followed by process kill",
                    "raw": row['raw']
                })

    # Rule 2: User Escalation
    for _, row in log_df.iterrows():
        line = row['raw'].lower()
        if any(re.search(pattern, line) for pattern in SUSPICIOUS_RULES["User Escalation"]):
            anomalies.append({
                "timestamp": row['timestamp'],
                "actor": row['actor'],
                "action": row['action'],
                "target": row['target'],
                "rule": "User Escalation",
                "reason": "User attempted privilege escalation",
                "raw": row['raw']
            })

    # Rule 3: Unexpected File Deletion
    for _, row in log_df.iterrows():
        line = row['raw'].lower()
        if any(re.search(pattern, line) for pattern in SUSPICIOUS_RULES["Unexpected File Deletion"]):
            anomalies.append({
                "timestamp": row['timestamp'],
                "actor": row['actor'],
                "action": row['action'],
                "target": row['target'],
                "rule": "Unexpected File Deletion",
                "reason": "Suspicious file deletion detected",
                "raw": row['raw']
            })

    # Rule 4: Unusual Port Usage
    for _, row in log_df.iterrows():
        line = row['raw'].lower()
        if re.search(SUSPICIOUS_RULES["Unusual Port Usage"][0], line):
            anomalies.append({
                "timestamp": row['timestamp'],
                "actor": row['actor'],
                "action": row['action'],
                "target": row['target'],
                "rule": "Unusual Port Usage",
                "reason": "Outbound connection on high port (>49152)",
                "raw": row['raw']
            })

    # Rule 5: Persistence Behavior
    for _, row in log_df.iterrows():
        line = row['raw'].lower()
        if re.search(SUSPICIOUS_RULES["Persistence Behavior"][0], line):
            anomalies.append({
                "timestamp": row['timestamp'],
                "actor": row['actor'],
                "action": row['action'],
                "target": row['target'],
                "rule": "Persistence Behavior",
                "reason": "Registry modification for persistence detected",
                "raw": row['raw']
            })

    # Rule 6: Security Tools Disabled
    for _, row in log_df.iterrows():
        line = row['raw'].lower()
        if re.search(SUSPICIOUS_RULES["Security Tools Disabled"][0], line):
            anomalies.append({
                "timestamp": row['timestamp'],
                "actor": row['actor'],
                "action": row['action'],
                "target": row['target'],
                "rule": "Security Tools Disabled",
                "reason": "Attempt to disable security tools detected",
                "raw": row['raw']
            })

    # Rule 7: Exfiltration Suspicion
    for _, row in log_df.iterrows():
        line = row['raw'].lower()
        if any(re.search(pattern, line) for pattern in SUSPICIOUS_RULES["Exfiltration Suspicion"]):
            anomalies.append({
                "timestamp": row['timestamp'],
                "actor": row['actor'],
                "action": row['action'],
                "target": row['target'],
                "rule": "Exfiltration Suspicion",
                "reason": "Possible data exfiltration attempt detected",
                "raw": row['raw']
            })

    # Rule 8: Unusual Login Time (12am–6am)
    for _, row in log_df.iterrows():
        if row['timestamp'] and 0 <= row['timestamp'].hour < 6:
            anomalies.append({
                "timestamp": row['timestamp'],
                "actor": row['actor'],
                "action": row['action'],
                "target": row['target'],
                "rule": "Unusual Login Time",
                "reason": f"Login at {row['timestamp'].strftime('%H:%M')}",
                "raw": row['raw']
            })

    # Rule 9: Multiple Failed Logins
    failed_attempts = {}
    for _, row in log_df.iterrows():
        if "login failed" in row['raw'].lower():
            key = row['actor'] or "unknown"
            failed_attempts[key] = failed_attempts.get(key, 0) + 1
            if failed_attempts[key] >= 5:
                anomalies.append({
                    "timestamp": row['timestamp'],
                    "actor": row['actor'],
                    "action": row['action'],
                    "target": row['target'],
                    "rule": "Multiple Failed Logins",
                    "reason": f"{failed_attempts[key]} consecutive login failures",
                    "raw": row['raw']
                })

    return pd.DataFrame(anomalies)

# --- Streamlit UI Logic ---
st.set_page_config(page_title="Corporate Log Anomaly Detector", layout="wide")
st.title("🛡️ Corporate Log Anomaly Detection System")
st.markdown("Upload log files to detect suspicious behavior")

uploaded_files = st.file_uploader("Upload Log Files", type=["log", "txt"], accept_multiple_files=True)

if uploaded_files:
    all_lines = []
    for file in uploaded_files:
        lines = file.read().decode("utf-8").splitlines()
        all_lines.extend(lines)

    with st.spinner("Parsing logs..."):
        parsed_data = [extract_log_fields(line) for line in all_lines]
        valid_logs = [entry for entry in parsed_data if 'timestamp' in entry]
        corrupted = [entry['raw'] for entry in parsed_data if 'error' in entry]

        log_df = pd.DataFrame(valid_logs)
        anomaly_df = detect_suspicious_activity(log_df)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Lines Parsed", len(all_lines))
    col2.metric("Corrupted Lines", len(corrupted))
    col3.metric("Anomalies Detected", len(anomaly_df))

    if not anomaly_df.empty:
        st.subheader("🔍 Flagged Anomalies")
        filter_rule = st.selectbox("Filter by rule", ["All"] + list(set(anomaly_df['rule'])))
        keyword = st.text_input("Search by keyword")
        start_date = st.date_input("Start Date", value=min(anomaly_df['timestamp']).date())
        end_date = st.date_input("End Date", value=max(anomaly_df['timestamp']).date())

        filtered = anomaly_df.copy()
        if filter_rule != "All":
            filtered = filtered[filtered['rule'] == filter_rule]
        if keyword:
            filtered = filtered[filtered['raw'].str.contains(keyword, case=False)]
        filtered = filtered[(filtered['timestamp'] >= pd.to_datetime(start_date)) &
                            (filtered['timestamp'] <= pd.to_datetime(end_date))]

        # Convert timestamps to string before JSON dump
        filtered_for_export = filtered.copy()
        filtered_for_export['timestamp'] = filtered_for_export['timestamp'].astype(str)

        st.dataframe(filtered[['timestamp', 'rule', 'actor', 'action', 'target', 'reason']])

        # Generate reports
        csv_report = filtered.to_csv(index=False)
        json_report = json.dumps(filtered_for_export.to_dict(orient='records'), indent=2)

        # HTML Report
        html_table = filtered[['timestamp', 'rule', 'actor', 'action', 'target', 'reason']].to_html(index=False, classes='table')
        html_chart = ""
        if not filtered.empty:
            rule_counts = Counter(filtered['rule'])
            df_chart = pd.Series(rule_counts).reset_index()
            df_chart.columns = ['Rule', 'Count']
            html_chart = df_chart.to_html(index=False)

        html_content = (template.render(table=html_table, chart=html_chart) 
                        if template else DEFAULT_HTML_TEMPLATE.replace("{{ table }}", html_table).replace("{{ chart }}", html_chart))

        # PDF Report
        try:
            pdf_path = "./anomalies_report.pdf"
            pdf = pdfkit.from_string(html_content, False)
        except:
            pdf = None

        # Export options
        st.subheader("📥 Export Reports")
        col_csv, col_json, col_html, col_pdf = st.columns(4)
        col_csv.download_button("Download CSV", data=csv_report, file_name="anomalies_report.csv")
        col_json.download_button("Download JSON", data=json_report, file_name="anomalies_report.json")
        col_html.download_button("Download HTML", data=html_content, file_name="anomalies_report.html", mime="text/html")
        if pdf:
            col_pdf.download_button("Download PDF", data=pdf, file_name="anomalies_report.pdf", mime="application/pdf")
        else:
            col_pdf.warning("PDF generation failed. Install wkhtmltopdf.")

        # Stats
        st.subheader("📊 Anomaly Statistics")
        if not filtered.empty:
            rule_counts = Counter(filtered['rule'])
            st.bar_chart(pd.Series(rule_counts))

    else:
        st.info("No anomalies detected.")

    with st.expander("View Corrupted Lines"):
        st.text_area("", "\n".join(corrupted), height=300, label_visibility="collapsed")

else:
    st.info("Please upload log files to begin analysis")