import re
import streamlit as st
import pandas as pd
import json
from datetime import datetime
from collections import Counter
import plotly.express as px
import plotly.io as pio
from io import StringIO, BytesIO
import pdfkit  # Requires installation

# --- Corporate Event Classification Rules ---
CORPORATE_CLASSIFICATION_RULES = {
    'Authentication': [
        r'XR-LOG!@OPN_usr',
        r'XR-LOG!@CLS_usr'
    ],
    'Process': [
        r'XR-EXEC!@RUN',
        r'XR-SHDW!@KILL_proc'
    ],
    'File': [
        r'XR-FILE!@MOD',
        r'XR-DEL!@DEL'
    ],
    'Network': [
        r'XR-CONN!@IP',
        r'XR-PORT!@'
    ],
    'Security': [
        r'XR-SHDW!@',
        r'XR-ALERT!@'
    ],
    'System': [
        r'XR-SYS!@',
        r'XR-BOOT!@'
    ]
}

# --- Log Parsing Functions ---
def parse_corporate_log_line(line):
    try:
        parts = line.split('|')
        if len(parts) < 2:
            return None
            
        ts_part = parts[0].split(':')[-1]
        try:
            timestamp = datetime.fromtimestamp(int(ts_part))
        except ValueError:
            timestamp = None
            
        event_part = parts[1]
        event_type = event_part.split('!')[0] if '!' in event_part else 'UNKNOWN'
        
        actor = re.search(r'usr:([a-zA-Z0-9]+)', event_part)
        actor = actor.group(1) if actor else None
        
        target = re.search(r'=>([^\s]+)|@IP:([\d.]+)', event_part)
        target = target.group(1) or target.group(2) if target else None
        
        action = re.search(r'@([A-Z]+)_', event_part)
        action = action.group(1) if action else None
        
        category = classify_corporate_event(event_part)
        
        return {
            'timestamp': timestamp,
            'event_type': event_type,
            'actor': actor,
            'action': action,
            'target': target,
            'category': category,
            'raw': line.strip()
        }
    except Exception as e:
        return {'raw': line.strip(), 'error': str(e)}

def classify_corporate_event(event_str):
    for category, patterns in CORPORATE_CLASSIFICATION_RULES.items():
        for pattern in patterns:
            if re.search(pattern, event_str):
                return category
    return 'Unknown'

# --- Processing Functions ---
def process_corporate_logs(lines):
    parsed_events = []
    corrupted_lines = []
    
    for line in lines:
        parsed = parse_corporate_log_line(line)
        if parsed and 'timestamp' in parsed and parsed['timestamp']:
            parsed_events.append(parsed)
        else:
            corrupted_lines.append(parsed['raw'] if parsed else line)
    
    df = pd.DataFrame(parsed_events)
    if not df.empty:
        df = df.sort_values('timestamp')
    return df, corrupted_lines

# --- Reporting Functions ---
def generate_timeline_csv(df):
    output = StringIO()
    df.to_csv(output, index=False)
    return output.getvalue()

def generate_category_report(df):
    report = {
        'total_events': len(df),
        'categories': dict(Counter(df['category'])),
        'top_actors': dict(Counter(df['actor']).most_common(5)),
        'frequent_targets': dict(Counter(df['target']).most_common(5))
    }
    return report

def generate_html_report(df, fig_html):
    """Generate HTML report with timeline table and graph."""
    html_table = df[['timestamp', 'category', 'actor', 'action', 'target']].to_html(index=False, classes='table table-striped')

    html_content = f"""
    <html>
    <head>
        <title>Corporate Log Analysis Report</title>
        <style>
            body {{ font-family: Arial; padding: 20px; }}
            h2 {{ color: #2c3e50; }}
            .table {{ border-collapse: collapse; width: 100%; }}
            .table th, .table td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <h1>Corporate Log Analysis Report</h1>
        <h2>Event Timeline</h2>
        {html_table}
        <h2>Event Categories</h2>
        {fig_html}
    </body>
    </html>
    """
    return html_content

# --- Streamlit UI ---
def main():
    st.set_page_config(page_title="Corporate Log Analyzer", layout="wide")
    st.title("Corporate Log Analysis System")
    st.markdown("Upload log files for security and operational analysis")
    
    uploaded_files = st.file_uploader(
        "Upload Corporate Log Files",
        type=["log", "txt"],
        accept_multiple_files=True
    )
    
    if uploaded_files:
        all_lines = []
        for file in uploaded_files:
            lines = file.read().decode("utf-8").splitlines()
            all_lines.extend(lines)
            
        with st.spinner("Processing corporate logs..."):
            df, corrupted = process_corporate_logs(all_lines)
            
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Valid Events", len(df))
        col2.metric("Corrupted Lines", len(corrupted))
        col3.metric("Time Coverage", 
                   f"{df['timestamp'].min().strftime('%Y-%m-%d')} to {df['timestamp'].max().strftime('%Y-%m-%d')}" 
                   if not df.empty else "N/A")
        
        st.subheader("Security Event Categories")
        if not df.empty:
            cat_counts = Counter(df['category'])
            fig = px.bar(pd.DataFrame(cat_counts.items(), columns=['Category', 'Count']), 
                         x='Category', y='Count', color='Category',
                         title="Corporate Event Classification")
            fig_html = pio.to_html(fig, full_html=False)
            st.plotly_chart(fig)
        else:
            st.warning("No valid events to categorize")
            
        st.subheader("Event Timeline")
        if not df.empty:
            st.dataframe(df[['timestamp', 'category', 'actor', 'action', 'target']])
            
            st.subheader("Download Reports")
            csv_report = generate_timeline_csv(df)
            json_report = generate_category_report(df)
            html_report = generate_html_report(df, fig_html) if not df.empty and 'fig_html' in locals() else ""
            
            col1, col2, col3 = st.columns(3)
            
            col1.download_button(
                "Download Timeline (CSV)",
                data=csv_report,
                file_name="corporate_timeline.csv",
                mime="text/csv"
            )

            col2.download_button(
                "Download Report (HTML)",
                data=html_report,
                file_name="corporate_report.html",
                mime="text/html"
            )

            try:
                pdf = pdfkit.from_string(html_report, False)
                col3.download_button(
                    "Download Report (PDF)",
                    data=pdf,
                    file_name="corporate_report.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.error("PDF generation failed. Make sure `wkhtmltopdf` is installed.")
            
            col4, _ = st.columns(2)
            col4.download_button(
                "Download Summary (JSON)",
                data=json.dumps(json_report, indent=2),
                file_name="corporate_summary.json",
                mime="application/json"
            )
        else:
            st.warning("No timeline data available")
            
        if corrupted:
            with st.expander("View Corrupted Lines"):
                st.text_area("Corrupted Entries", "\n".join(corrupted), height=200)
    else:
        st.info("Please upload corporate log files to begin analysis")

if __name__ == "__main__":
    main()