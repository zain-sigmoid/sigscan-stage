"""
Consolidated Code Review Tool - Main Application
Unified interface for all code analysis modules.
"""

# Flake8: noqa: E501

import streamlit as st
import asyncio
import os
import logging
import re
import json
from typing import List
import zipfile
import shutil
import io
import pandas as pd
from utils.logs_service.logger import AppLogger
from utils.logs_service.logs_view import LogsCheck

AppLogger.init(
    level=logging.INFO,
    log_to_file=True,
)
logger = AppLogger.get_logger(__name__)

# Import core components
from utils.prod_shift import Extract
from core.engine import UnifiedAnalysisEngine
from utils.severity_mapping import Severity
from core.models import (
    AnalysisConfiguration,
    ConsolidatedReport,
    SeverityLevel,
    FindingCategory,
    UnifiedFinding,
)
from core.interfaces import analyzer_registry

# Import analyzers
from analyzers.secrets_analyzer import HardcodedSecretsAnalyzer

# Page configuration
st.set_page_config(
    page_title="Consolidated Code Review Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


class ConsolidatedCodeReviewApp:
    """Main application class for the consolidated code review tool."""

    def __init__(self):
        self.engine = UnifiedAnalysisEngine()
        self._initialize_analyzers()
        self._initialize_session_state()

    def _initialize_analyzers(self):
        """Initialize and register all analyzers."""
        # Register hardcoded secrets analyzer
        secrets_analyzer = HardcodedSecretsAnalyzer()
        analyzer_registry.register(secrets_analyzer)

        # Register robustness analyzer
        from analyzers.robustness_analyzer import RobustnessAnalyzer

        robustness_analyzer = RobustnessAnalyzer()
        analyzer_registry.register(robustness_analyzer)

        # Register PII/PHI analyzer
        from analyzers.pii_analyzer import PIIAnalyzer

        pii_analyzer = PIIAnalyzer()
        analyzer_registry.register(pii_analyzer)

        # Register testability analyzer
        from analyzers.testability_analyzer import TestabilityAnalyzer

        testability_analyzer = TestabilityAnalyzer()
        analyzer_registry.register(testability_analyzer)

        # Register observability analyzer
        from analyzers.observability_analyzer import ObservabilityAnalyzer

        observability_analyzer = ObservabilityAnalyzer()
        analyzer_registry.register(observability_analyzer)

        # Register readability analyzer
        from analyzers.readability_analyzer import ReadabilityAnalyzer

        readability_analyzer = ReadabilityAnalyzer()
        analyzer_registry.register(readability_analyzer)

        # Register injection analyzer
        from analyzers.injection_analyzer import InjectionAnalyzer

        injection_analyzer = InjectionAnalyzer()
        analyzer_registry.register(injection_analyzer)

        from analyzers.maintainability_analyzer import MaintainabilityAnalyzer

        maintainability_analyzer = MaintainabilityAnalyzer()
        analyzer_registry.register(maintainability_analyzer)

        from analyzers.performance_analyzer import PerformanceAnalyzer

        performance_analyzer = PerformanceAnalyzer()
        analyzer_registry.register(performance_analyzer)

        from analyzers.compliance_analyzer import ComplianceAnalyzer

        compliance_analyzer = ComplianceAnalyzer()
        analyzer_registry.register(compliance_analyzer)

        logger.info(
            f"Registered {len(analyzer_registry.list_analyzer_names())} analyzers"
        )

    def _initialize_session_state(self):
        """Initialize Streamlit session state."""
        if "current_report" not in st.session_state:
            st.session_state.current_report = None
        if "analysis_history" not in st.session_state:
            st.session_state.analysis_history = []
        if "analysis_running" not in st.session_state:
            st.session_state.analysis_running = False
        if "selected_analyzers_count" not in st.session_state:
            st.session_state.selected_analyzers_count = len(
                analyzer_registry.get_all_analyzers()
            )
        if "show_glossary" not in st.session_state:
            st.session_state.show_glossary = False
        if "resolved_target_path" not in st.session_state:
            st.session_state.resolved_target_path = ""

    def run(self):
        """Run the main application."""
        self._render_header()

        # Sidebar for configuration
        with st.sidebar:
            self._render_sidebar()

        # Main content area
        if st.session_state.get("show_glossary", False):
            # Clear the flag and show glossary
            st.session_state.show_glossary = False
            self._render_glossary_faq()
        elif st.session_state.current_report:
            self._render_analysis_results()
        else:
            self._render_welcome_screen()

    def _render_header(self):
        """Render the application header."""
        st.title("🔍 Code Review Tool")
        st.markdown(
            """
        **Unified analysis platform** combining multiple security, quality, and compliance checkers.
        
        - 🔐 **Security Analysis**: Secrets, vulnerabilities, injection attacks
        - 🛡️ **Privacy Compliance**: PII/PHI detection, GDPR/HIPAA compliance  
        - 📊 **Code Quality**: Readability, maintainability, performance
        - 🧪 **Testing & Observability**: Test coverage, logging analysis
        - 🧰 **Maintainability**: Cyclomatic Complexity, Maintainability Index
        - ⚙️ **Performance**: Inefficient code patterns, resource usage
        """
        )

        # Status indicator
        if st.session_state.analysis_running:
            st.info("🔄 Analysis in progress...")
        elif st.session_state.current_report:
            findings_count = len(st.session_state.current_report.findings)
            st.success(f"✅ Analysis complete - {findings_count} findings")

    def _render_sidebar(self):
        """Render the sidebar configuration."""
        st.header("📋 Analysis Configuration")
        CODE_EXTS = (".py",)

        # Target selection
        target_type = st.radio(
            "Analysis Target:",
            ["📁 Project Zip File", "📄 Single File"],
            help="Choose whether to analyze a directory or single file",
        )

        if target_type == "📁 Project Zip File":
            # target_path = st.text_input(
            #     "Directory Path:",
            #     placeholder="/path/to/your/project",
            #     help="Enter the full path to the directory to analyze",
            # )
            target_path = st.file_uploader(
                "Upload your project as a .zip", type=["zip"]
            )
            if target_path is not None:
                dest = Extract.resolve_dest_folder(arg="dir")
                if dest.exists():
                    shutil.rmtree(dest)
                with zipfile.ZipFile(io.BytesIO(target_path.read())) as z:
                    Extract.safe_extract_zip(z, dest)
                project_root = Extract.find_best_project_root(dest, CODE_EXTS)
                files_count = Extract.count_code_files(project_root, CODE_EXTS)
                st.success(f"Unzipped Successfully, Found {files_count} Files")
                st.session_state.resolved_target_path = project_root
        else:
            uploaded = st.file_uploader("Upload your python file", type=["py"])
            if uploaded:
                dest = Extract.resolve_dest_folder(arg="file")
                dest.mkdir(parents=True, exist_ok=True)

                file_path = dest / uploaded.name
                with open(file_path, "wb") as f:
                    f.write(uploaded.read())

                st.success(f"Uploaded file: {'/'.join(str(file_path).split('/')[-2:])}")
                target_path = str(file_path)
                st.session_state.resolved_target_path = target_path

        # Analyzer selection
        st.subheader("🔧 Analyzers")
        available_analyzers = analyzer_registry.list_analyzer_names()

        if available_analyzers:
            selected_analyzers = st.multiselect(
                "Select Analyzers:",
                available_analyzers,
                default=available_analyzers,
                help="Choose which analyzers to run",
                key="selected_analyzers",
            )
            # Update session state with selected analyzers count
            st.session_state.selected_analyzers_count = len(selected_analyzers)
        else:
            st.warning("No analyzers available")
            selected_analyzers = []
            st.session_state.selected_analyzers_count = 0

        # Analysis options
        st.subheader("⚙️ Options")

        st.info(
            "💡 **Tip**: All severity levels are captured during analysis. You can filter results after analysis is complete."
        )

        parallel_execution = st.checkbox(
            "Parallel Execution",
            value=True,
            help="Run analyzers in parallel for faster execution",
        )

        include_low_confidence = st.checkbox(
            "Include Low Confidence",
            value=False,
            help="Include findings with low confidence scores",
        )

        # Advanced options
        with st.expander("🔬 Advanced Options"):
            timeout_seconds = st.slider(
                "Timeout (seconds):",
                min_value=30,
                max_value=900,
                value=450,
                help="Maximum time to wait for analysis completion",
            )

            max_findings = st.number_input(
                "Max Findings per Analyzer:",
                min_value=10,
                max_value=10000,
                value=1000,
                help="Limit the number of findings per analyzer",
            )

        # Run analysis button
        st.markdown("---")

        if st.button(
            "🚀 Run Analysis",
            type="primary",
            disabled=st.session_state.analysis_running
            or not st.session_state.resolved_target_path,
            help="Start comprehensive code analysis",
        ):
            analysis_root = st.session_state.resolved_target_path
            if target_path and os.path.exists(analysis_root):
                self._run_analysis(
                    target_path=analysis_root,
                    selected_analyzers=set(selected_analyzers),
                    parallel_execution=parallel_execution,
                    include_low_confidence=include_low_confidence,
                    timeout_seconds=timeout_seconds,
                    max_findings=max_findings,
                )
            else:
                st.error("Please provide a valid file or directory path")

        # Analysis history
        if st.session_state.analysis_history:
            st.subheader("📚 Analysis History")
            for i, report in enumerate(
                reversed(st.session_state.analysis_history[-5:])
            ):
                timestamp = report.timestamp.strftime("%Y-%m-%d %H:%M")
                findings_count = len(report.findings)

                if st.button(
                    f"{timestamp} ({findings_count} findings)",
                    key=f"history_{i}",
                    help="Load this analysis result",
                ):
                    st.session_state.current_report = report
                    st.rerun()

        # Help section
        st.markdown("---")
        uploaded = st.file_uploader("Upload your output JSON file", type=["json"])
        if st.button("See Results"):
            if uploaded:
                try:
                    data = json.load(uploaded)  # file-like works directly
                except Exception as e:
                    st.error(f"Invalid JSON: {e}")
                    st.stop()

                try:
                    report = ConsolidatedReport.from_dict(d=data)
                except Exception as e:
                    st.error(f"Could not convert JSON into ConsolidatedReport")
                    st.stop()

                # Now it's a real object with methods like get_summary_stats()
                st.session_state.current_report = report
                st.session_state.analysis_history.append(report)
                st.session_state.analysis_running = False
                st.success("Loaded report from JSON.")
            else:
                st.error("Please upload a valid JSON File")

        st.markdown("---")
        st.subheader("❓ Need Help?")

        if st.button(
            "📚 Open Glossary & FAQ", help="Access comprehensive help and documentation"
        ):
            # Set a session state to show glossary
            st.session_state.show_glossary = True
            st.rerun()

        st.caption(f"🔖 Version:1.8.1")

    def _run_analysis(
        self,
        target_path: str,
        selected_analyzers: set,
        parallel_execution: bool,
        include_low_confidence: bool,
        timeout_seconds: int,
        max_findings: int,
    ):
        """Run the analysis with given configuration."""
        st.session_state.analysis_running = True

        # Create analysis configuration
        config = AnalysisConfiguration(
            target_path=st.session_state.resolved_target_path,
            enabled_analyzers=selected_analyzers,
            severity_threshold=SeverityLevel.INFO,  # Always capture all severities
            parallel_execution=parallel_execution,
            include_low_confidence=include_low_confidence,
            timeout_seconds=timeout_seconds,
            max_findings_per_analyzer=max_findings,
        )

        # Show progress
        progress_placeholder = st.empty()
        with progress_placeholder.container():
            st.info("🔄 Starting analysis...")
            progress_bar = st.progress(0)

            def make_progress_cb(total_analyzers: int):
                # Capture state in a closure
                completed = {"n": 0}

                def _cb(increment: int = 1, stage: str | None = None):
                    completed["n"] += increment
                    pct = int(100 * completed["n"] / max(total_analyzers, 1))
                    label = (
                        f"{stage or 'Analyzing'}: {completed['n']}/{total_analyzers}"
                    )
                    # Update the UI progress bar
                    progress_bar.progress(pct, text=label)

                return _cb

        try:
            # Run analysis (using asyncio for async function)
            selected_analyzers = st.session_state.get("selected_analyzers_count", 10)
            progress_cb = make_progress_cb(selected_analyzers)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # report = loop.run_until_complete(
            #     self.engine.analyze(config, progress_cb=progress_cb)
            # )
            try:
                report = loop.run_until_complete(
                    self.engine.analyze(config, progress_cb=progress_cb)
                )
                # Update session state
                st.session_state.current_report = report
                st.session_state.analysis_history.append(report)
                st.session_state.analysis_running = False

                # Clear progress indicator
                progress_placeholder.empty()
                if getattr(report, "timed_out", False):
                    st.warning(
                        f"⏱️ Timeout reached after {config.timeout_seconds}s. "
                        "Partial results are displayed below."
                    )
                else:
                    st.success(
                        f"✅ Analysis completed! Found {len(report.findings)} findings."
                    )

                # Success message
                # st.success(f"✅ Analysis completed! Found {len(report.findings)} findings.")
                st.rerun()

            except asyncio.CancelledError:
                # Make sure the UI shows *something*
                st.error(f"Analysis exited due to timeout ({config.timeout_seconds}s).")

        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            st.session_state.analysis_running = False
            progress_placeholder.empty()
            st.error(f"❌ Analysis failed")

    def _render_welcome_screen(self):
        """Render the welcome screen when no analysis has been run."""
        col1, col2 = st.columns([2, 1])

        with col1:
            st.markdown("## 👋 Welcome to the Code Review Tool")

            st.markdown(
                """
            This unified platform combines multiple specialized analyzers to provide 
            comprehensive code analysis across security, quality, privacy, and compliance dimensions.
            
            ### 🚀 Getting Started
            
            1. **Select your target** in the sidebar (file or directory)
            2. **Choose analyzers** to run based on your needs
            3. **Configure options** like execution mode and confidence settings
            4. **Run analysis** and review the consolidated results
            
            ### 🔍 Available Analysis Types
            """
            )

            # Show available analyzers
            analyzers = analyzer_registry.get_all_analyzers()
            for analyzer in analyzers:
                with st.expander(f"🔧 {analyzer.get_name().replace('_', ' ').title()}"):
                    st.write(f"**Version:** {analyzer.get_version()}")
                    st.write(
                        f"**Status:** {'✅ Enabled' if analyzer.is_enabled() else '❌ Disabled'}"
                    )

                    if hasattr(analyzer, "get_security_categories"):
                        categories = analyzer.get_security_categories()
                        if categories:
                            category_html = "".join(
                                [
                                    f"<span style='display:inline-block; background-color:#f0f2f6; color:#333; "
                                    f"padding:4px 18px; margin:4px; border-radius:16px; font-size:14px; "
                                    f"font-weight:500; border:1px solid #d0d7de; font-size:12px'>{cat}</span>"
                                    for cat in categories
                                ]
                            )
                        st.markdown(
                            f"**Categories:**<br>{category_html}",
                            unsafe_allow_html=True,
                        )
                    if hasattr(analyzer, "get_quality_categories"):
                        categories = analyzer.get_quality_categories()
                        if categories:
                            category_html = "".join(
                                [
                                    f"<span style='display:inline-block; background-color:#f0f2f6; color:#333; "
                                    f"padding:4px 18px; margin:4px; border-radius:16px; font-size:14px; "
                                    f"font-weight:500; border:1px solid #d0d7de; font-size:12px'>{cat}</span>"
                                    for cat in categories
                                ]
                            )
                        st.markdown(
                            f"**Categories:**<br>{category_html}",
                            unsafe_allow_html=True,
                        )

                        # st.write(f"**Categories:** {', '.join(categories)}")

        with col2:
            st.markdown("## 📊 Quick Stats")

            # Show analyzer statistics
            total_analyzers = len(analyzer_registry.get_all_analyzers())
            selected_count = st.session_state.get(
                "selected_analyzers_count", total_analyzers
            )

            st.metric("Total Analyzers", total_analyzers)
            st.metric("Selected Analyzers", selected_count)

            if st.session_state.analysis_history:
                st.metric("Previous Analyses", len(st.session_state.analysis_history))

    def _render_analysis_results(self):
        """Render the analysis results."""
        report = st.session_state.current_report

        # Summary section
        self._render_executive_summary(report)

        # Create tabs for different views
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
            [
                "🔍 All Findings",
                "📊 Dashboard",
                "🗂️ By Category",
                "📈 Metrics",
                "📋 Export",
                "📚 Glossary & FAQ",
            ]
        )

        with tab1:
            self._render_all_findings(report)

        with tab2:
            self._render_dashboard(report)

        with tab3:
            self._render_findings_by_category(report)

        with tab4:
            self._render_metrics(report)

        with tab5:
            self._render_export_options(report)

        with tab6:
            self._render_glossary_faq()

    def _render_executive_summary(self, report: ConsolidatedReport):
        """Render executive summary."""
        st.markdown("## 📋 Executive Summary")

        summary_stats = report.get_summary_stats()

        # Key metrics
        col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

        with col1:
            st.metric("Total Findings", summary_stats["total_findings"])

        with col2:
            st.metric(
                "Critical", summary_stats["critical_findings"], delta_color="inverse"
            )

        with col3:
            st.metric("High", summary_stats["high_findings"], delta_color="inverse")

        with col4:
            st.metric("Medium", summary_stats["medium_findings"])

        with col5:
            st.metric("Low", summary_stats["low_findings"])

        with col6:
            st.metric("Info", summary_stats["info_findings"])

        with col7:
            st.metric("Analysis Time", f"{report.total_execution_time:.1f}s")

        # Risk assessment
        if summary_stats["critical_findings"] > 0:
            st.error("🚨 **Critical issues found** - Immediate attention required")
        elif summary_stats["high_findings"] > 0:
            st.warning("⚠️ **High severity issues found** - Should be addressed soon")
        elif summary_stats["total_findings"] > 0:
            st.info("ℹ️ **Issues found** - Review and address as needed")
        else:
            st.success("✅ **No issues found** - Code looks good!")

    def _base_type(self, title: str) -> str:
        if not title:
            return ""
        if ":" in title:
            part_after = title.split(":", 1)[1].strip()
        else:
            part_after = title.strip()
        return part_after

    def _render_all_findings(self, report: ConsolidatedReport):
        """Render all findings in a list."""
        findings = report.findings

        if not findings:
            st.info("🎉 No findings to display!")
            return
        # titles = {f.title for f in findings}
        titles = {self._base_type(f.title) for f in findings}
        paths = {os.path.basename(f.location.file_path) for f in findings}
        # Filters
        col1, col2, col3 = st.columns(3)

        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity:",
                [s.value.title() for s in SeverityLevel],
                default=[s.value.title() for s in SeverityLevel],
            )
            search_term = st.text_input(
                "🔍 Search findings:", placeholder="Enter search term..."
            )

        with col2:
            category_filter = st.multiselect(
                "Filter by Category:",
                [c.value.title() for c in FindingCategory],
                default=[c.value.title() for c in FindingCategory],
            )

        with col3:
            options = ["All"] + sorted(titles)
            finding_type_filter = st.selectbox(
                f"Filter by Type (Total Filters **{len(options)}**)",
                options,  # titles is already set of strings
                index=0,
                # default=sorted(titles),
            )
            valid_paths = [
                p
                for p in paths
                if re.match(
                    r"^[\w\-/\\]+\.py$", p.strip()
                )  # matches file.py or dir/file.py only
            ]
            options_two = ["All"] + sorted(valid_paths)
            finding_file_filter = st.selectbox(
                f"Filter by Files (Total Unique Files **{len(valid_paths)}**)",
                options_two,
                index=0,
            )

        # Apply filters
        filtered_findings = self._apply_finding_filters(
            findings,
            severity_filter,
            category_filter,
            search_term,
            finding_type_filter,
            finding_file_filter,
        )

        st.write(f"Showing {len(filtered_findings)} of {len(findings)} findings")

        # Display findings
        for i, finding in enumerate(filtered_findings):
            self._render_single_finding(finding, i)

    def _render_vars(self, value):
        if isinstance(value, list):
            # render each element as bullet
            st.markdown("\n".join(f"- {d}" for d in value))

        elif isinstance(value, dict):
            # nice collapsible JSON viewer
            st.markdown(f"**Details**")
            st.json(value)

        elif isinstance(value, str):
            # plain text
            st.markdown(f"**Details:** {value}")

        else:
            # fallback: just dump
            st.write(f"**Details:** {value}")

    def _render_single_finding(self, finding: UnifiedFinding, index: int):
        """Render a single finding."""
        file_name = os.path.basename(finding.location.file_path or "Unknown")
        space_count = 200
        padding = "&nbsp;" * 10

        # expander_title = f"**{finding.severity.value.upper()}** - {finding.title} {padding} *`{file_name}`*"
        expander_title = (
            f"**{finding.severity.value.upper()}** - {finding.title} *`{file_name}`*"
        )

        with st.expander(expander_title, expanded=index < 5):
            col1, col2 = st.columns([3, 1])

            with col1:
                # st.markdown(f"**Description:** {finding.description}")
                st.markdown(
                    f"**Description:**  {finding.description}",
                    unsafe_allow_html=True,
                )

                if finding.details is not None:
                    details = finding.details
                    self._render_vars(details)

                if finding.clubbed is not None:
                    try:
                        df = pd.DataFrame(finding.clubbed)
                        df.index = range(1, len(df) + 1)
                        with st.expander(f"**{finding.title}**"):
                            st.table(df)
                    except Exception as e:
                        # traceback.print_exc()
                        logger.error(f"Failed to render clubbed data: {str(e)}")
                        with st.expander(
                            f"{finding.title} -- {os.path.basename(finding.location.file_path)}"
                        ):
                            st.write(f"There is some problem showing this info")

                if finding.location.file_path:
                    location_str = f"{finding.location.file_path}"
                    if finding.location.line_number:
                        location_str += f":{finding.location.line_number}"
                    st.markdown(f"**Location:** `{location_str}`")

                if finding.code_snippet:
                    num_lines = finding.code_snippet.count("\n") + 1
                    height = 100 if num_lines > 3 else None
                    st.markdown("**Code:**")
                    st.code(finding.code_snippet, wrap_lines=True, height=height)

                if finding.remediation_guidance:
                    st.markdown(f"**Remediation:** {finding.remediation_guidance}")

            with col2:
                st.markdown(f"**Category:** {finding.category.value.title()}")
                st.markdown(f"**Analyzer:** {finding.source_analyzer}")
                st.markdown(f"**Confidence:** {finding.confidence_score:.0%}")
                if finding.rule_id is not None:
                    st.markdown(f"**Rule ID:** {str(finding.rule_id).upper()}")

                if finding.cwe_id:
                    st.markdown(f"**CWE:** {finding.cwe_id}")

                if finding.compliance_frameworks:
                    st.markdown(
                        f"**Compliance:** {', '.join(finding.compliance_frameworks)}"
                    )

    def _render_dashboard(self, report: ConsolidatedReport):
        """Render dashboard view."""
        st.markdown("## 📊 Analysis Dashboard")

        # TODO: Implement dashboard with charts and visualizations
        st.info(
            "Dashboard with charts and visualizations will be implemented in Phase 4"
        )

        # For now, show basic statistics
        summary_stats = report.get_summary_stats()

        # Severity breakdown chart
        st.subheader("Severity Distribution")
        severity_data = {
            "Critical": summary_stats["critical_findings"],
            "High": summary_stats["high_findings"],
            "Medium": summary_stats["medium_findings"],
            "Low": summary_stats["low_findings"],
            "Info": summary_stats["info_findings"],
        }
        st.bar_chart(severity_data)

        # Category breakdown
        st.subheader("Category Distribution")
        category_data = {
            category.value.title(): summary_stats.get(f"{category.value}_findings", 0)
            for category in FindingCategory
        }
        st.bar_chart(category_data)

    def _render_findings_by_category(self, report: ConsolidatedReport):
        """Render findings organized by category."""
        st.markdown("## 🗂️ Findings by Category")

        for category in FindingCategory:
            category_findings = report.get_findings_by_category(category)

            if category_findings:
                with st.expander(
                    f"**{category.value.title()}** ({len(category_findings)} findings)"
                ):
                    for finding in category_findings[:10]:  # Show first 10
                        self._render_single_finding(finding, 0)

                    if len(category_findings) > 10:
                        st.info(f"... and {len(category_findings) - 10} more findings")

    def _render_metrics(self, report: ConsolidatedReport):
        """Render analysis metrics."""
        st.markdown("## 📈 Analysis Metrics")

        # Analyzer performance
        st.subheader("Analyzer Performance")

        metrics_data = []
        for metric in report.analysis_metrics:
            metrics_data.append(
                {
                    "Analyzer": metric.analyzer_name,
                    "Execution Time (s)": f"{metric.execution_time_seconds:.2f}",
                    "Files Analyzed": metric.files_analyzed,
                    "Findings": metric.findings_count,
                    "Status": "✅ Success" if metric.success else "❌ Failed",
                }
            )

        if metrics_data:
            st.table(metrics_data)

        # Summary metrics
        st.subheader("Summary")
        st.json(report.get_summary_stats())

    def get_message(self, finding: dict) -> str:
        """
        Generate a human-readable message string for CSV export
        from analyzer-specific 'clubbed' dictionaries.
        """
        clubbed = finding.get("clubbed") or {}
        if not isinstance(clubbed, dict):
            return str(clubbed)

        # --- Common case: explicit messages already present ---
        if "messages" in clubbed and clubbed["messages"]:
            # Join messages with semicolon for readability
            return "; ".join(map(str, clubbed["messages"]))

        # --- Observability Analyzer ---
        if all(k in clubbed for k in ["lines", "function", "Coverage Percentages"]):
            funcs = ", ".join(map(str, clubbed.get("function", [])))
            coverage = clubbed.get("Coverage Percentages", "N/A")
            return f"Functions: {funcs} | Coverage: {coverage}%"

        # --- Performance Analyzer ---
        if any(k in clubbed for k in ["Time Complexities", "Function", "issue"]):
            funcs = clubbed.get("Functions", [])
            times = clubbed.get("Time Complexities", [])
            issues = clubbed.get("Issue", [])
            # Build function:complexity pairs if both exist
            if funcs and times:
                pairs = [f"{fn} ({tc})" for fn, tc in zip(funcs, times)]
                msg = "; ".join(pairs)
            else:
                msg = ", ".join(funcs or times or [])
            if issues:
                msg += f" | Issues: {', '.join(map(str, issues))}"
            return msg or "Performance issues detected"

        # --- Robustness Analyzer ---
        if "prefix" in clubbed:
            prefixes = clubbed.get("prefix", [])
            if isinstance(prefixes, list):
                prefixes = ", ".join(map(str, prefixes))
            return f"Dictionary access patterns: {prefixes}"

        # --- Secrets Analyzer ---
        if "snippets" in clubbed:
            snippets = clubbed.get("snippets", [])
            if isinstance(snippets, list):
                snippets = "; ".join(map(str, snippets))
            return f"Hardcoded secret snippets: {snippets}"

        # --- Testability Analyzer ---
        if "untested_functions" in clubbed:
            funcs = clubbed.get("untested_functions", [])
            if isinstance(funcs, list):
                funcs = ", ".join(map(str, funcs))
            return f"Untested functions: {funcs}"

        # --- Default: fallback to lines if present ---
        if "lines" in clubbed:
            return f"Lines: {', '.join(map(str, clubbed['lines']))}"

        # --- Final fallback ---
        return ""

    def _render_export_options(self, report: ConsolidatedReport):
        """Render export options."""
        st.markdown("## 📋 Export Results")

        exportable_data = bool(
            report.findings
            or report.analysis_metrics
            or report.summary
            or report.compliance_status
        )

        if not exportable_data:
            st.info("No report data is available for export yet.")
            return

        timestamp_str = report.timestamp.strftime("%Y%m%d_%H%M%S")
        base_filename = f"code_review_report_{timestamp_str}"

        findings_payload = []
        for finding in report.findings:
            location = finding.location
            findings_payload.append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "details": finding.details,
                    "clubbed": finding.clubbed,
                    "severity": finding.severity.value,
                    "category": finding.category.value,
                    "confidence_score": finding.confidence_score,
                    "file_path": location.file_path,
                    "line_number": location.line_number,
                    "column": location.column,
                    "analyzer": finding.source_analyzer,
                    "rule_id": finding.rule_id,
                    "cwe_id": finding.cwe_id,
                    "owasp_category": finding.owasp_category,
                    "tags": sorted(finding.tags),
                    "timestamp": finding.timestamp.isoformat(),
                }
            )

        metrics_payload = [
            {
                "analyzer_name": metric.analyzer_name,
                "execution_time_seconds": metric.execution_time_seconds,
                "files_analyzed": metric.files_analyzed,
                "findings_count": metric.findings_count,
                "error_count": metric.error_count,
                "warnings_count": metric.warnings_count,
                "success": metric.success,
                "error_message": metric.error_message,
            }
            for metric in report.analysis_metrics
        ]

        compliance_payload = [
            {
                "framework_name": status.framework_name,
                "total_checks": status.total_checks,
                "passed_checks": status.passed_checks,
                "failed_checks": status.failed_checks,
                "compliance_percentage": status.compliance_percentage,
                "critical_failures": status.critical_failures,
            }
            for status in report.compliance_status
        ]

        export_payload = {
            "metadata": {
                "report_id": report.id,
                "generated_at": report.timestamp.isoformat(),
                "target_path": report.target_path,
                "total_execution_time": report.total_execution_time,
            },
            "summary": report.get_summary_stats(),
            "findings": findings_payload,
            "analysis_metrics": metrics_payload,
            "compliance": compliance_payload,
            "analysis_config": report.analysis_config,
        }

        import json
        from io import StringIO
        import csv

        from datetime import datetime
        from enum import Enum
        from pathlib import PurePath

        def _json_ready(value):
            if isinstance(value, dict):
                return {key: _json_ready(val) for key, val in value.items()}
            if isinstance(value, (list, tuple)):
                return [_json_ready(item) for item in value]
            if isinstance(value, set):
                return sorted(_json_ready(item) for item in value)
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, PurePath):
                return str(value)
            try:
                json.dumps(value)
            except TypeError:
                return str(value)
            return value

        def _json_default(o):
            """Fallback converter for non-serializable types."""
            import datetime, pathlib, enum, dataclasses

            if isinstance(o, datetime.datetime):
                return o.isoformat()
            if isinstance(o, datetime.date):
                return o.isoformat()
            if isinstance(o, (pathlib.Path,)):
                return str(o)
            if isinstance(o, (set, frozenset)):
                return list(o)
            if isinstance(o, enum.Enum):
                return o.value
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)

            # Try model_dump, to_dict, dict, json (Pydantic, etc.)
            for attr in ("to_dict", "dict", "model_dump", "json"):
                if hasattr(o, attr) and callable(getattr(o, attr)):
                    try:
                        v = getattr(o, attr)()
                        if isinstance(v, str):
                            return json.loads(v)
                        return v
                    except Exception:
                        pass

            return str(o)

        report_bytes = json.dumps(report, default=_json_default)

        def _as_str_path(p):
            # convert Path/str/None -> str
            return "" if p is None else os.fspath(p)

        def _join_list(values, sep=","):
            if not values:
                return ""
            if not isinstance(values, (list, tuple, set)):
                return str(values)
            return sep.join(map(str, values))

        def join_lines(lines) -> str:
            if not lines:
                return ""
            # use pipe and wrap in brackets -> [65|66|176|179]
            return "[" + ", ".join(map(str, lines)) + "]"

        csv_buffer = StringIO()
        fieldnames = [
            "id",
            "severity",
            "category",
            "clubbed_lines",
            "functions",
            "clubbed_messages",
            "file_path",
            "line_number",
            "title",
            "description",
            "details",
            "analyzer",
            "confidence_score",
        ]
        csv_writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        csv_writer.writeheader()

        for f in findings_payload:
            clubbed = f.get("clubbed") or {}
            lines = clubbed.get("lines", [])
            # msg = self.get_message(f)
            msg = self.get_message(
                {
                    **f,
                    "clubbed": {
                        k: v
                        for k, v in clubbed.items()
                        if k.lower() not in ["function", "untested_functions"]
                    },
                }
            )

            functions = (
                clubbed.get("function")
                or clubbed.get("Function")
                or clubbed.get("untested_functions")
                or []
            )

            row = {
                "id": f.get("id", ""),
                "severity": f.get("severity", ""),
                "category": f.get("category", ""),
                "clubbed_lines": join_lines(lines),  # e.g. "83,109"
                "functions": _join_list(functions, sep=", "),
                "clubbed_messages": _join_list(msg, sep=" | "),  # e.g. "msg1 | msg2"
                "file_path": _as_str_path(f.get("file_path")),
                "line_number": f.get("line_number", ""),
                "title": f.get("title", ""),
                "description": f.get("description", ""),
                "details": f.get("details", ""),
                "analyzer": f.get("analyzer", ""),
                "confidence_score": f.get("confidence_score", ""),
            }
            csv_writer.writerow(row)

        findings_csv = csv_buffer.getvalue()

        col_json, col_csv = st.columns([3, 3])

        with col_json:
            st.download_button(
                "📄 Download JSON",
                report_bytes,
                file_name=f"{base_filename}.json",
                mime="application/json",
            )
            with st.expander("Preview JSON"):
                try:
                    st.json(report_bytes)
                except Exception as e:
                    logger.error(f"Error in JSON Preview: {e}")
                    st.write("Unable to Preview")

        with col_csv:
            st.download_button(
                "📊 Download CSV",
                findings_csv,
                file_name=f"{base_filename}.csv",
                mime="text/csv",
                disabled=not findings_payload,
            )
            with st.expander("Preview CSV"):
                try:
                    df = pd.read_csv(StringIO(findings_csv))
                    st.dataframe(df)
                except Exception as e:
                    logger.error(f"Error in CSV Preview: {e}")
                    st.write("Unable to Preview")

    def _apply_finding_filters(
        self,
        findings: List[UnifiedFinding],
        severity_filter: List[str],
        category_filter: List[str],
        search_term: str,
        finding_type_filter: List[str],
        finding_file_filter: List[str],
    ) -> List[UnifiedFinding]:
        """Apply filters to findings list."""
        filtered = findings

        def _lc(x):
            return (x or "").strip().lower()

        # Severity filter
        if severity_filter:
            severity_values = [s.lower() for s in severity_filter]
            filtered = [f for f in filtered if f.severity.value in severity_values]

        # Category filter
        if category_filter:
            category_values = [c.lower() for c in category_filter]
            filtered = [f for f in filtered if f.category.value in category_values]

        # Search filter
        if search_term:
            search_lower = search_term.lower()
            filtered = [
                f
                for f in filtered
                if search_lower in f.title.lower()
                or search_lower in f.description.lower()
                or search_lower in f.location.file_path.lower()
            ]
        if finding_type_filter and finding_type_filter != "All":
            type_values = {_lc(finding_type_filter)}
            filtered = [
                f
                for f in filtered
                if _lc(self._base_type(getattr(f, "title", ""))) in type_values
            ]

        if finding_file_filter and finding_file_filter != "All":
            file_values = {finding_file_filter}
            filtered = [
                f
                for f in filtered
                if os.path.basename(f.location.file_path) in file_values
            ]

        return filtered

    def _render_glossary_faq(self):
        """Render the glossary and FAQ section."""
        # Add back button
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("← Back to Home", help="Return to the main page"):
                st.session_state.show_glossary = False
                st.rerun()

        with col2:
            st.markdown("## 📚 Glossary & FAQ")

        # Create tabs for different FAQ categories
        faq_tab1, faq_tab2, faq_tab3, faq_tab4 = st.tabs(
            [
                "🚀 Getting Started",
                "🔧 Analyzers Guide",
                "❓ Common Questions",
                "📖 Glossary",
            ]
        )

        with faq_tab1:
            self._render_getting_started_faq()

        with faq_tab2:
            self._render_analyzers_guide()

        with faq_tab3:
            self._render_common_questions()

        with faq_tab4:
            self._render_glossary()

    def _render_getting_started_faq(self):
        """Render getting started FAQ section."""
        st.markdown("### 🚀 Getting Started Guide")

        st.markdown(
            """
        #### How to Navigate the App

        1. **Sidebar Configuration**: Use the sidebar to configure your analysis
           - Select target (file or directory)
           - Choose analyzers to run
           - Configure analysis options

        2. **Main Content Area**: View results and findings
           - Executive summary with key metrics
           - Detailed findings in organized tabs
           - Export options for reports

        3. **Results Tabs**: Explore findings in different ways
           - **All Findings**: Complete list with filters
           - **Dashboard**: Visual charts and statistics
           - **By Category**: Grouped by security/quality categories
           - **Metrics**: Performance and analysis metrics
           - **Export**: Download results in various formats
        """
        )

        st.markdown("#### How to Run Analysis")

        st.markdown(
            """
        **Step-by-Step Process:**

        1. **Select Target**:
           - Choose between directory or single file analysis
           - Upload the zip file of folder for directory analysis and single python file for file analysis

        2. **Choose Analyzers**:
           - Select from available security and quality analyzers
           - All analyzers are enabled by default
           - You can customize based on your needs

        3. **Configure Options**:
           - **Parallel Execution**: Run analyzers simultaneously (faster)
           - **Include Low Confidence**: Include less certain findings
           - **Timeout**: Maximum analysis time (30-600 seconds)
           - **Max Findings**: Limit findings per analyzer

        4. **Run Analysis**:
           - Click "🚀 Run Analysis" button
           - Monitor progress in the main area
           - Results appear automatically when complete

        5. **Review Results**:
           - Check executive summary for overview
           - Filter findings by severity and category
           - Export results for further analysis
        """
        )

        st.markdown("#### Best Practices")

        st.markdown(
            """
        - **Start with all analyzers** to get comprehensive results
        - **Use parallel execution** for faster analysis of large projects
        - **Set appropriate timeout** based on project size
        - **Review critical and high severity findings first**
        - **Export results** for team sharing and tracking
        """
        )

    def _render_analyzers_guide(self):
        """Render analyzers guide section."""
        st.markdown("### 🔧 Analyzers Guide")

        analyzers = analyzer_registry.get_all_analyzers()

        for analyzer in analyzers:
            with st.expander(f"🔧 {analyzer.get_name().replace('_', ' ').title()}"):
                st.markdown(f"**Version:** {analyzer.get_version()}")
                st.markdown(
                    f"**Status:** {'✅ Enabled' if analyzer.is_enabled() else '❌ Disabled'}"
                )

                # Get analyzer-specific information
                if hasattr(analyzer, "get_security_categories"):
                    categories = analyzer.get_security_categories()
                    if categories:
                        st.markdown(f"**Security Categories:** {', '.join(categories)}")

                if hasattr(analyzer, "get_quality_categories"):
                    categories = analyzer.get_quality_categories()
                    if categories:
                        st.markdown(f"**Quality Categories:** {', '.join(categories)}")

                if hasattr(analyzer, "get_compliance_frameworks"):
                    frameworks = analyzer.get_compliance_frameworks()
                    if frameworks:
                        st.markdown(
                            f"**Compliance Frameworks:** {', '.join(frameworks)}"
                        )

                # Analyzer-specific descriptions
                analyzer_descriptions = {
                    "hardcoded_secrets": {
                        "description": "Detects hardcoded secrets, API keys, passwords, and sensitive credentials in your codebase using Gitleaks.",
                        "what_it_finds": [
                            "API keys and tokens",
                            "Database passwords",
                            "SSH private keys",
                            "AWS access keys",
                            "OAuth secrets",
                            "Encryption keys",
                        ],
                        "tools_used": "Gitleaks",
                        "severity_focus": "Critical, High and Medium severity findings",
                        "df": Severity.hardcoded_secret(),
                    },
                    "pii_phi": {
                        "description": "Identifies Personally Identifiable Information (PII) and Protected Health Information (PHI) to ensure compliance with data protection regulations.",
                        "what_it_finds": [
                            "Email addresses",
                            "Phone numbers",
                            "Social Security Numbers",
                            "Credit card numbers",
                            "Medical record numbers",
                            "Driver's license numbers",
                            "IP addresses",
                        ],
                        "compliance": "GDPR, HIPAA, CCPA, PCI DSS",
                        "tools_used": "AST, Custom Patterns",
                        "severity_focus": "Critical, High and Medium severity findings",
                        "df": Severity.pii_phi(),
                    },
                    "readability": {
                        "description": "Evaluates code readability, style, and maintainability using Pylint and custom checks.",
                        "what_it_finds": [
                            "Naming convention violations",
                            "Missing documentation",
                            "Code formatting issues",
                            "Complexity problems",
                            "Style guide violations",
                        ],
                        "tools_used": "Pylint, custom patterns",
                        "severity_focus": "Medium, Low and Info severity findings",
                        "df": Severity.readability(),
                    },
                    "robustness": {
                        "description": "Analyzes code robustness, error handling, and defensive programming practices.",
                        "what_it_finds": [
                            "Missing error handling",
                            "Unsafe operations",
                            "Resource management issues",
                            "Input validation problems",
                            "Exception handling gaps",
                        ],
                        "tools_used": "bandit, mypy, semgrep",
                        "severity_focus": "High, Medium and Low severity findings",
                        "df": Severity.robustness(),
                    },
                    "testability": {
                        "description": "Evaluates code testability and suggests improvements for better testing coverage.",
                        "what_it_finds": [
                            "Untestable code patterns",
                            "Missing test coverage",
                            "Complex dependencies",
                            "Hard-to-mock components",
                            "Test infrastructure issues",
                        ],
                        "tools_used": "AST, Custom Patterns",
                        "severity_focus": "Medium and Low severity findings",
                        "df": Severity.testability(),
                    },
                    "observability": {
                        "description": "Analyzes logging, monitoring, and observability practices in your code. Finds Critical functions, Critical Functions are functions in the codebase that handle essential operations such as error management, data validation, user authentication, or core business logic",
                        "what_it_finds": [
                            "Missing logging statements",
                            "Inadequate error logging",
                            "Performance monitoring gaps",
                            "Debug information issues",
                            "Observability best practices",
                        ],
                        "tools_used": "AST",
                        "severity_focus": "High, Medium, Low and Info severity findings",
                        "df": Severity.observability(),
                    },
                    "injection": {
                        "description": "Detects potential injection vulnerabilities and unsafe input handling.",
                        "what_it_finds": [
                            "SQL injection vulnerabilities",
                            "Command injection risks",
                            "XSS vulnerabilities",
                            "Path traversal issues",
                            "Unsafe input handling",
                        ],
                        "tools_used": "Custom Patterns",
                        "severity_focus": "Critical, High and Medium severity findings",
                        "df": Severity.injection(),
                    },
                    "maintainability": {
                        "description": "Assesses code maintainability using metrics like Cyclomatic Complexity and Maintainability Index.",
                        "what_it_finds": [
                            "High complexity functions",
                            "Low maintainability index",
                            "Function duplication",
                            "Branches in the code",
                        ],
                        "tools_used": "radon cc, radon mi, AST",
                        "severity_focus": "High, Medium and Info severity findings",
                        "image": ["assets/crr.png", "assets/ccinfo.png"],
                        "df": Severity.maintainability(),
                    },
                    "performance": {
                        "description": "Identifies performance bottlenecks and inefficient code patterns.",
                        "what_it_finds": [
                            "Time Complexity issues",
                            "Naive Search patterns",
                            "Naive Sort patterns",
                            "Inefficient Data Structures",
                        ],
                        "tools_used": "AST",
                        "severity_focus": "High, Medium and Low severity findings",
                        "df": Severity.performance(),
                    },
                    "compliance": {
                        "description": "Checks for compliance with various regulatory frameworks and standards.",
                        "what_it_finds": [
                            "Copyright violations",
                            "License issues",
                            "Data protection compliance",
                        ],
                        "tools_used": "Scancode, Semgrep",
                        "severity_focus": "Medium, Low and Info severity findings",
                        "df": Severity.compliance(),
                    },
                }

                analyzer_name = analyzer.get_name()
                if analyzer_name in analyzer_descriptions:
                    desc = analyzer_descriptions[analyzer_name]
                    st.markdown(f"**Description:** {desc['description']}")

                    st.markdown("**What it finds:**")
                    for item in desc.get("what_it_finds", []):
                        st.markdown(f"- {item}")

                    if "tools_used" in desc:
                        st.markdown(f"**Tools used:** {desc['tools_used']}")

                    if "compliance" in desc:
                        st.markdown(f"**Compliance:** {desc['compliance']}")

                    if "image" in desc:
                        st.markdown(
                            f"**Image** : Complexity Risk Ranking according to percent of Line of code in functions marked by Cyclomatic Complexity and Cyclomatic complexity scores"
                        )
                        images = desc.get("image")
                        if isinstance(images, list) and len(images) > 0:
                            # Create columns dynamically based on number of images
                            cols = st.columns(len(images))

                            for i, img in enumerate(images):
                                with cols[i]:
                                    st.image(img, caption=f"Figure {i+1}", width=420)
                        else:  # single image
                            st.image(images)

                    st.markdown(
                        f"**Severity focus:** {desc.get('severity_focus', 'All levels')}"
                    )
                    # st.dataframe(desc.get('df'), use_container_width=True, row_height=50)
                    df = pd.DataFrame(desc.get("df"))
                    # Convert to HTML and wrap long text using CSS
                    st.markdown(
                        """
                    <style>
                    .wrap-text-table td {
                        white-space: normal !important;
                        word-wrap: break-word !important;
                        text-align: left !important;
                        vertical-align: top !important;
                    }
                    </style>
                    """,
                        unsafe_allow_html=True,
                    )

                    # Render as HTML table with wrapping
                    st.markdown(
                        df.to_html(
                            classes="wrap-text-table", index=False, escape=False
                        ),
                        unsafe_allow_html=True,
                    )

    def _render_common_questions(self):
        """Render common questions FAQ section."""
        st.markdown("### ❓ Frequently Asked Questions")

        faqs = [
            {
                "question": "How long does analysis take?",
                "answer": "Analysis time depends on project size and selected analyzers. Small projects (1-10 files) typically take 30-60 seconds. Large projects (100+ files) may take 2-5 minutes. Parallel execution can significantly reduce analysis time.",
            },
            {
                "question": "What file types are supported?",
                "answer": "Currently, the tool primarily supports Python (.py) files. Some analyzers like the secrets analyzer can scan all file types for hardcoded credentials. Support for additional languages is planned for future releases.",
            },
            {
                "question": "How accurate are the findings?",
                "answer": "Findings include confidence scores to help you assess accuracy. High confidence findings (80%+) are typically very reliable. Lower confidence findings may be false positives and should be manually reviewed. You can filter by confidence level in the analysis options.",
            },
            {
                "question": "Can I exclude certain files or directories?",
                "answer": "Yes, you can configure exclusions in the advanced options. Common exclusions include test files, documentation, and third-party libraries. The tool automatically excludes some common patterns like __pycache__ directories.",
            },
            {
                "question": "How do I interpret the severity levels?",
                "answer": "Severity levels indicate the potential impact of findings:\n- **Critical**: Immediate security/compliance risk\n- **High**: Significant issue requiring prompt attention\n- **Medium**: Moderate issue that should be addressed\n- **Low**: Minor issue or improvement opportunity\n- **Info**: Informational finding with no immediate risk",
            },
            {
                "question": "What compliance frameworks are supported?",
                "answer": "The tool supports multiple compliance frameworks including GDPR, HIPAA, CCPA, PCI DSS, and various security standards. Each analyzer provides specific compliance mappings for relevant findings.",
            },
            {
                "question": "Can I export results for team sharing?",
                "answer": "Yes, you can export results in JSON format from the Export tab. This includes all findings with their details, metadata, and analysis metrics. Future versions will support additional export formats like PDF and CSV.",
            },
            {
                "question": "How do I handle false positives?",
                "answer": "False positives can be filtered by adjusting confidence thresholds or using the search/filter options. You can also exclude specific patterns or file types in the advanced configuration. The tool learns from your feedback to improve accuracy over time.",
            },
            {
                "question": "What's the difference between security and quality analyzers?",
                "answer": "Security analyzers focus on vulnerabilities, compliance, and data protection issues that could lead to security breaches. Quality analyzers focus on code maintainability, readability, and best practices that improve long-term code health.",
            },
            {
                "question": "Can I run this in CI/CD pipelines?",
                "answer": "Yes, the tool is designed to be integrated into CI/CD pipelines. You can run it as part of your build process to automatically check for issues. The JSON export format makes it easy to parse results programmatically.",
            },
        ]

        for i, faq in enumerate(faqs):
            with st.expander(f"Q{i+1}: {faq['question']}"):
                st.markdown(faq["answer"])

    def _render_glossary(self):
        """Render glossary section."""
        st.markdown("### 📖 Glossary")

        glossary_terms = [
            {
                "term": "Analysis Configuration",
                "definition": "Settings that control how the analysis is performed, including target paths, analyzer selection, and execution options.",
            },
            {
                "term": "Analyzer",
                "definition": "A specialized component that performs specific types of code analysis (e.g., security, quality, compliance).",
            },
            {
                "term": "CWE (Common Weakness Enumeration)",
                "definition": "A standard classification system for software security weaknesses and vulnerabilities.",
            },
            {
                "term": "Finding",
                "definition": "A specific issue or observation detected by an analyzer, including details about location, severity, and remediation guidance.",
            },
            {
                "term": "PII (Personally Identifiable Information)",
                "definition": "Data that can be used to identify a specific individual, such as names, addresses, or social security numbers.",
            },
            {
                "term": "PHI (Protected Health Information)",
                "definition": "Health information that is protected under privacy laws like HIPAA.",
            },
            {
                "term": "Severity Level",
                "definition": "Classification of findings based on potential impact: Critical, High, Medium, Low, or Info.",
            },
            {
                "term": "Confidence Score",
                "definition": "A percentage indicating how certain the analyzer is about a finding's accuracy.",
            },
            {
                "term": "Compliance Framework",
                "definition": "A set of rules and standards that organizations must follow (e.g., GDPR, HIPAA, PCI DSS).",
            },
            {
                "term": "Remediation Guidance",
                "definition": "Specific instructions on how to fix or address a detected issue.",
            },
            {
                "term": "False Positive",
                "definition": "A finding that appears to be an issue but is actually correct or acceptable code.",
            },
            {
                "term": "Parallel Execution",
                "definition": "Running multiple analyzers simultaneously to reduce total analysis time.",
            },
            {
                "term": "Code Location",
                "definition": "The specific file and line number where a finding was detected.",
            },
            {
                "term": "Unified Finding",
                "definition": "A standardized format for representing findings from different analyzers with consistent metadata.",
            },
            {
                "term": "Analysis Metrics",
                "definition": "Performance and statistical data about the analysis process, including execution time and file counts.",
            },
        ]

        for term in glossary_terms:
            with st.expander(f"**{term['term']}**"):
                st.markdown(term["definition"])


def show_main_app():
    app = ConsolidatedCodeReviewApp()
    app.run()


def main():
    """Main application entry point."""
    params = st.query_params
    view = params.get("view", "")
    if view == "logs":
        st.set_page_config(page_title="SigScan Logs", page_icon="🧾", layout="wide")
        if LogsCheck.check_admin_auth():
            LogsCheck.show_logs_page()
    else:
        show_main_app()


if __name__ == "__main__":
    main()
