import streamlit as st
import pandas as pd
from analyzer_pipeline import (
    parse_and_normalize_csv,
    generate_remediation_roadmap,
    SAMPLE_NESSUS_CSV
)

# =====================================================================
# 1. PAGE CONFIGURATION & CUSTOM CSS
# =====================================================================
st.set_page_config(
    page_title="Vulnerability Assessment Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for polished client-facing UI
st.markdown("""
    <style>
    .main {
        background-color: #f8f9fa;
    }
    .stMetric {
        background-color: #ffffff;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        border: 1px solid #e9ecef;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        font-weight: 600;
        font-size: 16px;
    }
    </style>
""", unsafe_allow_html=True)

# =====================================================================
# 2. HEADER & SIDEBAR CONTROLS
# =====================================================================
st.title("🛡️ Automated Vulnerability Assessment Report Analyzer")
st.markdown("Transform noisy scanner outputs into **business-aware, actionable remediation roadmaps**.")
st.divider()

with st.sidebar:
    st.header("📂 1. Input Data")
    uploaded_file = st.file_uploader("Upload CSV Scan Report", type=["csv"])
    use_sample = st.checkbox("Load Synthetic Sample Data", value=True)
    
    st.divider()
    st.header("⚙️ 2. Client Filters")
    min_risk_filter = st.slider("Minimum Business Risk Score", 0.0, 10.0, 0.0, 0.5)
    criticality_filter = st.multiselect(
        "Filter by Asset Criticality (1=Low, 5=Critical)",
        options=[1, 2, 3, 4, 5],
        default=[1, 2, 3, 4, 5]
    )

# =====================================================================
# 3. DATA INGESTION & PIPELINE
# =====================================================================
csv_data = None
if uploaded_file is not None:
    csv_data = uploaded_file.getvalue().decode("utf-8")
elif use_sample:
    csv_data = SAMPLE_NESSUS_CSV

if csv_data:
    raw_findings = parse_and_normalize_csv(csv_data)
    
    # Apply Client Filters
    findings = [
        f for f in raw_findings 
        if f.business_risk_score >= min_risk_filter and f.asset_criticality in criticality_filter
    ]
    
    if not findings:
        st.warning("No vulnerabilities match your current filter criteria. Adjust the sliders in the sidebar.")
    else:
        # =====================================================================
        # 4. EXECUTIVE METRICS ROW
        # =====================================================================
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Findings Ingested", len(raw_findings))
        col2.metric("Filtered Findings Displayed", len(findings))
        
        critical_count = sum(1 for f in findings if f.business_risk_score >= 7.5)
        col3.metric("🚨 Critical Business Risks", critical_count)
        
        highest_risk = findings[0].business_risk_score if findings else 0.0
        col4.metric("📈 Highest Risk Score", f"{highest_risk:.1f} / 10")
        
        st.write("") # Spacer

        # =====================================================================
        # 5. TABBED CLIENT WORKSPACE
        # =====================================================================
        tab1, tab2, tab3 = st.tabs([
            "📊 Executive Dashboard", 
            "📋 Full Findings Matrix", 
            "🎯 AI Remediation Plan"
        ])
        
        # --- TAB 1: VISUAL DASHBOARD ---
        with tab1:
            st.subheader("Vulnerability Severity Breakdown")
            df_visual = pd.DataFrame([
                {
                    "Asset": f.asset,
                    "Business Risk": f.business_risk_score,
                    "CVSS": f.cvss_score,
                    "Criticality": f.asset_criticality
                }
                for f in findings
            ])
            
            chart_col1, chart_col2 = st.columns([2, 1])
            with chart_col1:
                st.markdown("**Business Risk Score by Affected Asset**")
                st.bar_chart(df_visual.set_index("Asset")["Business Risk"], color="#ff4b4b")
            with chart_col2:
                st.markdown("**Asset Criticality vs. CVSS**")
                st.dataframe(df_visual[["Asset", "Criticality", "CVSS"]], use_container_width=True)

        # --- TAB 2: DATA MATRIX ---
        with tab2:
            st.subheader("Normalized & Prioritized Findings Table")
            st.markdown("Sorted descending by weighted **Business Risk Score**.")
            
            table_data = [
                {
                    "CVE ID": f.cve_id,
                    "Business Risk": f.business_risk_score,
                    "CVSS Base": f.cvss_score,
                    "Affected Asset": f.asset,
                    "Asset Criticality": f.asset_criticality,
                    "Vulnerability Title": f.title,
                }
                for f in findings
            ]
            
            st.dataframe(
                pd.DataFrame(table_data),
                use_container_width=True,
                column_config={
                    "Business Risk": st.column_config.NumberColumn(
                        "Business Risk",
                        help="Weighted score combining CVSS and Asset Criticality",
                        format="%.2f ⭐"
                    )
                }
            )

        # --- TAB 3: AI GENERATIVE ACTION PLAN ---
        with tab3:
            st.subheader("GenAI CISO Executive Summary & Action Plan")
            st.markdown("Generate plain-language context and ordered tasks via the **Gemini API**.")
            
            if st.button("✨ Generate Remediation Roadmap with Gemini", type="primary"):
                with st.spinner("Gemini is analyzing findings and structuring the roadmap..."):
                    try:
                        report = generate_remediation_roadmap(findings)
                        st.markdown(report)
                        
                        # Add a download button for the client
                        st.download_button(
                            label="📥 Download Executive Report (Markdown)",
                            data=report,
                            file_name="Executive_Vulnerability_Roadmap.md",
                            mime="text/markdown"
                        )
                    except Exception as e:
                        st.error(f"Error calling Gemini API: {e}. Ensure your GEMINI_API_KEY environment variable is set correctly.")
else:
    st.info("👋 Welcome! Please upload a CSV scan report or enable 'Load Synthetic Sample Data' in the left sidebar to begin.")