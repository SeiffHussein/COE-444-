"""
app.py - Streamlit dashboard. Run with:  python -m streamlit run app.py

The dashboard only CALLS modules and DISPLAYS their results:
    orchestrator.run_assessment()   the whole scan pipeline
    remediation.apply_fix()         the one guarded fix (after explicit approval)
    reporting.generate_*_report()   CSV / HTML export
It contains no scanner, ML or remediation logic. Nothing runs on import or on
page load - an assessment starts only when "Run assessment" is pressed.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

import config
from modules import ml_classifier, orchestrator, remediation, reporting, tool_utils
from schemas import ML_PRIORITIES, SEVERITIES, TOOLS

STATUS_ICONS = {"SUCCESS": "✅", "FAILED": "❌", "SKIPPED": "⏭️", "NOT_APPLICABLE": "➖"}


def main() -> None:
    import streamlit as st

    st.set_page_config(page_title=config.APP_NAME, layout="wide")
    st.title(config.APP_NAME)
    st.warning("**Authorized use only.** This tool scans only the lab targets listed in "
               "`config.AUTHORIZED_TARGETS`. Scanning systems without permission is illegal.")

    # ================================================================ sidebar: inputs
    with st.sidebar:
        st.header("Assessment")
        target = st.text_input("Target (IP or hostname)", value=config.AUTHORIZED_TARGETS[0]).strip()
        format_ok = tool_utils.validate_target(target)
        authorized = format_ok and tool_utils.is_authorized(target)
        st.write(("✅" if format_ok else "❌") + " Format " + ("valid" if format_ok else "invalid"))
        st.write(("✅" if authorized else "❌") + " Authorization: "
                 + ("target is authorized" if authorized else "NOT in AUTHORIZED_TARGETS"))
        st.caption("Authorized targets: " + ", ".join(config.AUTHORIZED_TARGETS))

        sample_mode = st.toggle("Sample mode (fixtures, no tools run)", value=config.SAMPLE_MODE_DEFAULT)
        st.subheader("Tools")
        st.checkbox("Nmap (always runs first)", value=True, disabled=True)
        options = {
            "run_nuclei": st.checkbox("Nuclei", value=True),
            "run_nikto": st.checkbox("Nikto (only if a web port is found)", value=True),
            "run_lynis": st.checkbox("Lynis (on the VM, over SSH)", value=True),
        }
        run = st.button("Run assessment", type="primary", disabled=not authorized)

    if sample_mode:
        st.info("**SAMPLE MODE is active** - results are labelled fixtures. No tool is run and no host is contacted.")
    else:
        st.error("**REAL MODE is active** - pressing *Run assessment* runs Nmap, Nuclei, Nikto and Lynis "
                 "against the target.")

    # ================================================================ run
    if run:
        with st.spinner("Running assessment..."):
            st.session_state["result"] = orchestrator.run_assessment(target, sample_mode, options)
        st.session_state.pop("reports", None)

    result: dict | None = st.session_state.get("result")
    if result is None:
        st.write("Choose a target in the sidebar and press **Run assessment**.")
        return

    label = "SAMPLE DATA" if result["is_sample"] else "REAL SCAN"
    st.caption(f"Scan **{result['scan_id']}** - target **{result['target']}** - {label} - "
               f"{result['started_at']} to {result['finished_at']} ({result['duration_s']} s)")
    for error in result["errors"]:
        st.error(error)

    # ================================================================ per-tool status
    st.subheader("Tool status")
    for column, tool in zip(st.columns(len(TOOLS) + 1), TOOLS + ("ML",)):
        scan = result["ml"] if tool == "ML" else result["scans"][tool]
        with column:
            st.markdown(f"**{tool}**")
            st.write(f"{STATUS_ICONS.get(scan['status'], '')} {scan['status']}")
            if tool != "ML":
                st.caption(f"{len(scan['findings'])} finding(s) - {scan['duration_s']} s")
            if scan["error"]:
                st.caption(scan["error"])

    findings = result["findings"]
    if not findings:
        st.write("No findings to show. Check the tool status above.")
        return
    table = pd.DataFrame(findings)

    # ================================================================ summary
    st.subheader("Summary")
    summary = orchestrator.summarize(result)
    columns = st.columns(1 + len(SEVERITIES))
    columns[0].metric("Total findings", summary["total"])
    for column, severity in zip(columns[1:], SEVERITIES):
        column.metric(severity, summary["by_severity"].get(severity, 0))
    columns = st.columns(1 + len(ML_PRIORITIES))
    columns[0].markdown("**ML priority**  \n(advisory)")
    for column, priority in zip(columns[1:], ML_PRIORITIES):
        column.metric(priority, summary["by_ml_priority"].get(priority, 0))

    chart_left, chart_right = st.columns(2)
    chart_left.caption("Findings by severity")
    chart_left.bar_chart(pd.Series({s: summary["by_severity"].get(s, 0) for s in SEVERITIES}, name="findings"))
    chart_right.caption("Findings by tool")
    chart_right.bar_chart(pd.Series({t: summary["by_tool"].get(t, 0) for t in TOOLS}, name="findings"))

    # ================================================================ findings table
    st.subheader("Findings")
    f1, f2, f3 = st.columns(3)
    tools = f1.multiselect("Tool", TOOLS, default=list(TOOLS))
    severities = f2.multiselect("Severity", SEVERITIES, default=list(SEVERITIES))
    priority_choices = list(ML_PRIORITIES) + ["(not classified)"]
    priorities = f3.multiselect("ML priority", priority_choices, default=priority_choices)
    view = table[table["source"].isin(tools) & table["severity"].isin(severities)
                 & table["ml_priority"].replace("", "(not classified)").isin(priorities)]
    st.dataframe(
        view[["title", "source", "original_severity", "severity", "ml_priority", "ml_action",
              "port", "service", "cve", "recommendation"]].rename(columns={
                  "source": "tool", "original_severity": "original severity", "severity": "normalized severity",
                  "ml_priority": "ML priority", "ml_action": "ML action"}),
        hide_index=True)
    st.caption("Original severity is the tool's own wording (empty if the tool gives none). "
               "ML priority/action are advisory labels from models trained on synthetic data.")

    st.markdown("**Evidence** (expand a finding)")
    for row in view.to_dict("records"):
        with st.expander(f"[{row['severity']}] {row['title']} - {row['source']}"):
            st.write(row["description"] or "_No description._")
            st.code(row["evidence"] or "-", language=None)
            st.write(f"Check ID: `{row['check_id'] or '-'}` - CVE: `{row['cve'] or '-'}` - Finding ID: `{row['id']}`")
            st.markdown(f"**Recommendation:** {row['recommendation']}")

    # ================================================================ remediation
    st.subheader("Remediation")
    fixable = [f for f in findings if f["remediation_supported"]]
    if not fixable:
        st.write("No finding with a supported automatic fix. All recommendations are manual.")
    else:
        st.caption("Exactly one automatic fix exists: disabling SSH root login on the lab VM. "
                   "Every other recommendation stays manual.")
        for finding in fixable:
            st.markdown(f"**{finding['title']}** on `{finding['target']}`")
            simulate = st.checkbox("Simulate only (walk the steps, change nothing)", value=True,
                                   key=f"sim_{finding['id']}")
            approved = st.checkbox("I approve disabling SSH root login on this VM (PermitRootLogin no).",
                                   key=f"ok_{finding['id']}")
            if not simulate and not config.ALLOW_AUTO_REMEDIATION:
                st.caption("Real fixes are switched off (config.ALLOW_AUTO_REMEDIATION is False).")
            if st.button("Simulate fix" if simulate else "Apply fix", key=f"fix_{finding['id']}",
                         disabled=not simulate and not approved):
                with st.spinner("Working..."):
                    result["remediation"] = remediation.apply_fix(finding, confirmed=approved, simulate=simulate)
        outcome = result.get("remediation")
        if outcome:
            if outcome["simulated"]:
                st.info(outcome["message"])
            elif outcome["applied"] and outcome["verified"]:
                st.success(outcome["message"])
            else:
                st.error(outcome["message"])
            st.write(f"Applied: **{outcome['applied']}** - Verified: **{outcome['verified']}**"
                     + (f" - Backup: `{outcome['backup_path']}`" if outcome["backup_path"] else ""))
            st.dataframe(pd.DataFrame(outcome["steps"]).assign(
                ok=lambda d: d["ok"].map({True: "OK", False: "FAILED"})), hide_index=True)

    # ================================================================ export
    st.subheader("Export report")
    if st.button("Generate CSV and HTML reports"):
        reports = []
        for kind, generate in (("csv", reporting.generate_csv_report), ("html", reporting.generate_html_report)):
            path = config.REPORTS_DIR / f"assessment_{result['scan_id']}.{kind}"
            try:
                reports.append({"kind": kind, "ok": True, "path": generate(result, str(path)), "error": ""})
            except RuntimeError as exc:
                reports.append({"kind": kind, "ok": False, "path": str(path), "error": str(exc)})
        st.session_state["reports"] = reports
    for report in st.session_state.get("reports", []):
        if not report["ok"]:
            st.error(f"{report['kind'].upper()} report FAILED: {report['error']}")
            continue
        st.success(f"{report['kind'].upper()} report saved: `{report['path']}`")
        name = Path(report["path"]).name
        st.download_button(f"Download {name}", Path(report["path"]).read_bytes(), file_name=name,
                           mime="text/csv" if report["kind"] == "csv" else "text/html", key=report["path"])

    # ================================================================ ML details
    with st.expander("ML model details"):
        st.write("Scores below are measured on **synthetic** data labelled by our own rules. "
                 "They say nothing about real-world performance.")
        for name, metrics in ml_classifier.model_metrics().items():
            if metrics:
                st.code(ml_classifier.format_metrics(name, metrics), language=None)
            else:
                st.write(f"{name} model: not available (train with `python -m modules.ml_classifier`).")


if __name__ == "__main__":
    main()
