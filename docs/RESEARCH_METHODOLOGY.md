# SOC-QA Intelligence — Research Methodology

## 1. Central Research Question
*How can process mining and explainable AI be integrated to evaluate SOC triage conformance, assess investigation quality and generate evidence-based audit insights?*

## 2. Methodological Safeguards
1. **Strict Separation of Telemetry vs. Analyst Actions**: Security telemetry events (`normalized_events`: Sysmon process creation, PowerShell Event ID 4104, Windows Security Event ID 4625, phishing emails) represent system observations of adversary or user activity. Analyst activity logs (`analyst_activities`: header inspection, SIEM queries, containment, escalation) represent human or SOAR workflow execution. PM4Py process discovery and conformance checking operate exclusively on `analyst_activities`.
2. **Observability Gaps vs. Procedural Errors**: A missing activity in an event log does not automatically prove an analyst failed to perform the step; it may indicate an unlogged manual action or tool integration gap. Therefore, **Process Conformance**, **Investigation Quality**, and **Documentation Quality** are evaluated and reported as orthogonal dimensions.
3. **Justified Playbook Drift**: Reference playbooks support conditional steps (`mandatory_status = 'conditional'`) and `permitted_alternative_actions`. Deviations triggered by legitimate operational constraints or alternative defensible actions are categorized separately from unjustified omissions.
4. **75-Case Controlled Experimental Benchmark**:
   - **Phishing** ([Zenodo Record 8339691](https://zenodo.org/records/8339691)): 15 Conformant, 10 Deviating (25 Total).
   - **Password Spraying — MITRE T1110.003** ([Splunk Attack Data](https://github.com/splunk/attack_data)): 15 Conformant, 10 Deviating (25 Total). Single-account brute-force attacks are excluded unless multi-account targeting is verified.
   - **Suspicious PowerShell — MITRE T1059.001** ([Splunk Attack Data](https://github.com/splunk/attack_data) & [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets)): 15 Conformant, 10 Deviating (25 Total).
   - **Total**: 45 Conformant, 30 Deviating (75 Total).
5. **Ground-Truth Isolation**: Ground-truth annotations reside exclusively in `ground_truth_labels` and are never passed to PM4Py discovery/conformance algorithms or Explainable AI prompts.
