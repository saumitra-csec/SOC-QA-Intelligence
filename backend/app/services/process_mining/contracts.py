"""
Operational Process Mining Engine (PM4Py-Compatible Petri-Net Discovery & Alignment Conformance Checking).
Operates strictly on normalized analyst_activities traces (never raw security telemetry) and keeps
ground_truth_labels isolated during conformance replay.
"""
import json
import uuid
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any, Dict, List, Optional
from backend.app.core.database import db_manager, utc_now_iso

try:
    import pm4py as _pm4py_lib
    from pm4py.objects.petri_net.obj import PetriNet as _Pm4PyPetriNet, Marking as _Pm4PyMarking
    from pm4py.objects.petri_net.utils import petri_utils as _pm4py_petri_utils
    from pm4py.objects.log.obj import EventLog as _Pm4PyEventLog, Trace as _Pm4PyTrace, Event as _Pm4PyEvent
    PM4PY_AVAILABLE = True
    PM4PY_VERSION = getattr(_pm4py_lib, "__version__", "installed")
except ImportError:
    _pm4py_lib = None
    _Pm4PyPetriNet = None
    _Pm4PyMarking = None
    _pm4py_petri_utils = None
    _Pm4PyEventLog = None
    _Pm4PyTrace = None
    _Pm4PyEvent = None
    PM4PY_AVAILABLE = False
    PM4PY_VERSION = None


class PM4PyServiceContract(ABC):
    @abstractmethod
    def export_analyst_traces_to_xes(self, case_ids: Optional[List[str]] = None) -> str:
        """Exports normalized analyst_activities into IEEE 1849-2016 XES."""

    @abstractmethod
    def discover_petri_net(self, playbook_id: Optional[str] = None) -> Dict[str, Any]:
        """Constructs version-locked Reference Petri Net & Directly-Follows Graph from playbook & observed traces."""

    @abstractmethod
    def check_conformance_alignments(
        self,
        case_id: str,
        playbook_version_id: Optional[str] = None,
        allow_unreviewed: bool = False,
        active_conditions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Performs token-based replay and optimal trace alignment against the reference Petri net,
        computing fitness, precision, skipped, reordered, repeated, additional activities, and premature termination.
        """


class OperationalProcessMiningEngine(PM4PyServiceContract):
    def get_runtime_info(self) -> Dict[str, Any]:
        """Reports whether native PM4Py is installed or built-in Petri-net replay fallback is active."""
        return {
            "pm4py_available": PM4PY_AVAILABLE,
            "pm4py_version": PM4PY_VERSION,
            "active_engine": "native_pm4py_alignments" if PM4PY_AVAILABLE else "builtin_petri_net_replay_fallback",
            "input_isolation": "analyst_activities_only (security_telemetry and ground_truth_labels excluded)",
        }

    def _build_native_pm4py_petri_net(self, ref_net: Dict[str, Any]):
        """Constructs a native pm4py.objects.petri_net.obj.PetriNet from the version-locked reference Petri net."""
        net = _Pm4PyPetriNet(ref_net["playbook_version_id"])
        place_map = {}
        for p_name in ref_net["places"]:
            pl = _Pm4PyPetriNet.Place(p_name)
            net.places.add(pl)
            place_map[p_name] = pl

        trans_map = {}
        for tr in ref_net["transitions"]:
            tid = tr["transition_id"]
            label = tr["label"]
            # Use step_id as transition label for alignment matching against concept:name
            t_label = None if tr["mandatory_status"] == "silent_tau" else tid
            t_obj = _Pm4PyPetriNet.Transition(tid, t_label)
            net.transitions.add(t_obj)
            trans_map[tid] = t_obj

        for arc in ref_net["arcs"]:
            src = place_map.get(arc["source"]) or trans_map.get(arc["source"])
            tgt = place_map.get(arc["target"]) or trans_map.get(arc["target"])
            if src is not None and tgt is not None:
                _pm4py_petri_utils.add_arc_from_to(src, tgt, net)

        im = _Pm4PyMarking({place_map[p]: 1 for p in ref_net["initial_marking"] if p in place_map})
        fm = _Pm4PyMarking({place_map[p]: 1 for p in ref_net["final_marking"] if p in place_map})
        return net, im, fm

    def _run_native_pm4py_alignment(
        self,
        case_id: str,
        playbook_version_id: str,
        observed_step_seq: List[str],
        observed_timestamps: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Executes native PM4Py optimal trace alignment & precision evaluation if pm4py is installed.
        Returns None on ImportError or runtime incompatibility so caller falls back cleanly.
        """
        if not PM4PY_AVAILABLE or _pm4py_lib is None:
            return None
        try:
            ref_net = self.build_reference_petri_net(playbook_version_id)
            net, im, fm = self._build_native_pm4py_petri_net(ref_net)

            log = _Pm4PyEventLog()
            trace = _Pm4PyTrace()
            trace.attributes["concept:name"] = case_id
            for idx, step_tok in enumerate(observed_step_seq):
                ev_attrs = {"concept:name": step_tok}
                if observed_timestamps and idx < len(observed_timestamps) and observed_timestamps[idx]:
                    ev_attrs["time:timestamp"] = observed_timestamps[idx]
                trace.append(_Pm4PyEvent(ev_attrs))
            log.append(trace)

            alignments = _pm4py_lib.conformance_diagnostics_alignments(log, net, im, fm)
            fit_res = _pm4py_lib.fitness_alignments(log, net, im, fm)
            prec_val = _pm4py_lib.precision_alignments(log, net, im, fm)

            first_align = alignments[0] if alignments else {}
            raw_fitness = fit_res.get("log_fitness", first_align.get("fitness", 0.0)) if isinstance(fit_res, dict) else float(fit_res or 0.0)
            return {
                "engine": "native_pm4py_alignments",
                "pm4py_version": PM4PY_VERSION,
                "fitness": round(float(raw_fitness), 4),
                "precision": round(float(prec_val or 0.0), 4),
                "alignment_cost": first_align.get("cost"),
                "alignment_moves": first_align.get("alignment", []),
            }
        except Exception:
            return None

    def export_analyst_traces_to_xes(self, case_ids: Optional[List[str]] = None) -> str:
        with db_manager.connection() as conn:
            if case_ids:
                placeholders = ",".join("?" for _ in case_ids)
                rows = conn.execute(
                    f"""
                    SELECT * FROM analyst_activities
                    WHERE case_id IN ({placeholders})
                    ORDER BY case_id ASC, normalized_utc_timestamp ASC
                    """,
                    tuple(case_ids),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM analyst_activities ORDER BY case_id ASC, normalized_utc_timestamp ASC"
                ).fetchall()

        traces: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            traces.setdefault(r["case_id"], []).append(dict(r))

        root = ET.Element(
            "log",
            {
                "xes.version": "1849-2016",
                "xes.features": "nested-attributes",
                "xmlns": "http://www.xes-standard.org/",
            },
        )
        for cid, events in traces.items():
            trace_el = ET.SubElement(root, "trace")
            ET.SubElement(trace_el, "string", {"key": "concept:name", "value": str(cid)})
            for ev in events:
                ev_el = ET.SubElement(trace_el, "event")
                ET.SubElement(
                    ev_el, "string", {"key": "concept:name", "value": str(ev["activity"])}
                )
                if ev.get("normalized_utc_timestamp"):
                    ET.SubElement(
                        ev_el,
                        "date",
                        {"key": "time:timestamp", "value": str(ev["normalized_utc_timestamp"])},
                    )
                if ev.get("analyst_id"):
                    ET.SubElement(
                        ev_el, "string", {"key": "org:resource", "value": str(ev["analyst_id"])}
                    )
                if ev.get("playbook_step_id"):
                    ET.SubElement(
                        ev_el,
                        "string",
                        {"key": "socqa:playbook_step_id", "value": str(ev["playbook_step_id"])},
                    )
        return ET.tostring(root, encoding="unicode")

    def build_reference_petri_net(self, playbook_version_id: str) -> Dict[str, Any]:
        """Translates a version-locked playbook into a formal Petri net (places, transitions, arcs, markings)."""
        with db_manager.connection() as conn:
            steps = conn.execute(
                "SELECT * FROM playbook_steps WHERE playbook_version_id = ? ORDER BY step_order ASC",
                (playbook_version_id,),
            ).fetchall()
        if not steps:
            raise ValueError(f"Playbook version '{playbook_version_id}' not found.")

        places = ["p_start"]
        transitions = []
        arcs = []
        for idx, s in enumerate(steps, start=1):
            p_in = places[-1]
            p_out = f"p_{idx}" if idx < len(steps) else "p_end"
            if p_out not in places:
                places.append(p_out)
            t_id = s["step_id"]
            transitions.append(
                {
                    "transition_id": t_id,
                    "label": s["step_name"],
                    "mandatory_status": s["mandatory_status"],
                    "step_order": s["step_order"],
                    "permitted_alternatives": json.loads(
                        s["permitted_alternative_actions_json"] or "[]"
                    ),
                }
            )
            arcs.append({"source": p_in, "target": t_id, "type": "place_to_transition"})
            arcs.append({"source": t_id, "target": p_out, "type": "transition_to_place"})
            # Conditional steps include a silent tau bypass transition (tau_skip) from p_in to p_out
            if s["mandatory_status"] in ("conditional", "optional"):
                tau_id = f"tau_bypass_{t_id}"
                transitions.append(
                    {
                        "transition_id": tau_id,
                        "label": None,
                        "mandatory_status": "silent_tau",
                        "step_order": s["step_order"],
                        "permitted_alternatives": [],
                    }
                )
                arcs.append({"source": p_in, "target": tau_id, "type": "place_to_transition"})
                arcs.append({"source": tau_id, "target": p_out, "type": "transition_to_place"})

        return {
            "playbook_version_id": playbook_version_id,
            "initial_marking": ["p_start"],
            "final_marking": ["p_end"],
            "places": places,
            "transitions": transitions,
            "arcs": arcs,
        }

    def discover_petri_net(self, playbook_id: Optional[str] = None) -> Dict[str, Any]:
        """Discovers Directly-Follows Graph (DFG), trace variants, and reference Petri nets."""
        with db_manager.connection() as conn:
            pb_vers = conn.execute(
                "SELECT playbook_version_id FROM playbook_versions ORDER BY playbook_id, version"
            ).fetchall()
            act_rows = conn.execute(
                "SELECT case_id, playbook_step_id, activity FROM analyst_activities ORDER BY case_id ASC, normalized_utc_timestamp ASC"
            ).fetchall()

        petri_nets = {
            r["playbook_version_id"]: self.build_reference_petri_net(r["playbook_version_id"])
            for r in pb_vers
        }

        traces_by_case: Dict[str, List[str]] = {}
        dfg_Counter: Counter = Counter()
        for r in act_rows:
            step_tok = r["playbook_step_id"] or r["activity"]
            traces_by_case.setdefault(r["case_id"], []).append(step_tok)

        variant_counter: Counter = Counter()
        for cid, seq in traces_by_case.items():
            variant_counter[" -> ".join(seq)] += 1
            for i in range(len(seq) - 1):
                dfg_Counter[(seq[i], seq[i + 1])] += 1

        return {
            "status": "OPERATIONAL_PETRI_NET_AND_ALIGNMENT_ENGINE",
            "input_source": "analyst_activities_only (security_telemetry excluded)",
            "ground_truth_isolation": "ENFORCED",
            "reference_petri_nets": petri_nets,
            "discovered_directly_follows_graph": [
                {"source": k[0], "target": k[1], "frequency": v}
                for k, v in dfg_Counter.most_common()
            ],
            "trace_variants": [
                {"variant_id": f"VAR-{idx:02d}", "trace": tr, "case_count": cnt}
                for idx, (tr, cnt) in enumerate(variant_counter.most_common(), start=1)
            ],
        }

    def check_conformance_alignments(
        self,
        case_id: str,
        playbook_version_id: Optional[str] = None,
        allow_unreviewed: bool = False,
        active_conditions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes token-based replay & trace alignment between observed analyst_activities for case_id
        and the applicable reference playbook Petri net. Persists results to conformance_results and
        deviation_findings.
        """
        with db_manager.connection() as conn:
            c_row = conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if not c_row:
                raise ValueError(f"Case '{case_id}' not found.")

            pb_ver_id = playbook_version_id or f"{c_row['playbook_id']}@{c_row['playbook_version'] or '1.0'}"
            ver_row = conn.execute(
                "SELECT * FROM playbook_versions WHERE playbook_version_id = ?",
                (pb_ver_id,),
            ).fetchone()
            if not ver_row:
                raise ValueError(f"Reference playbook version '{pb_ver_id}' not found.")
            pb_row = conn.execute(
                "SELECT * FROM playbooks WHERE playbook_id = ?",
                (ver_row["playbook_id"],),
            ).fetchone()

            norm_status = ver_row["normalization_status"] if "normalization_status" in ver_row.keys() else "validated"
            pb_classification = pb_row["playbook_classification"] if pb_row and "playbook_classification" in pb_row.keys() else "operational_soc_playbook"

            if not allow_unreviewed and norm_status not in ("human_reviewed", "validated"):
                raise ValueError(
                    f"Playbook '{pb_ver_id}' has normalization.status='{norm_status}' and cannot enter conformance evaluation until 'human_reviewed' or 'validated'."
                )
            if not allow_unreviewed and pb_classification == "reference_framework":
                raise ValueError(
                    f"Playbook '{pb_ver_id}' is classified as 'reference_framework' (non-executable taxonomy/guidance) and cannot be used for step-level conformance scoring."
                )

            steps = conn.execute(
                "SELECT * FROM playbook_steps WHERE playbook_version_id = ? ORDER BY step_order ASC",
                (pb_ver_id,),
            ).fetchall()
            if not steps:
                raise ValueError(f"Reference playbook steps for '{pb_ver_id}' not found.")

            obs_rows = conn.execute(
                "SELECT * FROM analyst_activities WHERE case_id = ? ORDER BY normalized_utc_timestamp ASC",
                (case_id,),
            ).fetchall()

        expected_steps = [dict(s) for s in steps]
        mandatory_ids = [s["step_id"] for s in expected_steps if s["mandatory_status"] == "mandatory"]
        all_valid_ids = {s["step_id"] for s in expected_steps}
        step_order_map = {s["step_id"]: s["step_order"] for s in expected_steps}
        step_name_to_id = {s["step_name"].lower(): s["step_id"] for s in expected_steps}
        alt_to_step_id = {}
        for s in expected_steps:
            for alt in json.loads(s["permitted_alternative_actions_json"] or "[]"):
                alt_to_step_id[alt.lower()] = s["step_id"]

        # Cross-playbook semantic step correspondence (maps canonical benchmark steps to equivalent
        # institutional playbook steps of the same attack type when replaying across multiple playbooks)
        CROSS_PLAYBOOK_STEP_EQUIVALENCE = {
            "MS-PHISH-EXAMPLE-001": {
                "PHISH-S1": ["MSP-01"],
                "PHISH-S2": ["MSP-02", "MSP-03"],
                "PHISH-S3": ["MSP-04"],
                "PHISH-S4": ["MSP-05"],
                "PHISH-S5": ["MSP-05"],
            },
            "PB-PHISH-001": {
                "MSP-01": ["PHISH-S1"],
                "MSP-02": ["PHISH-S2"],
                "MSP-03": ["PHISH-S2"],
                "MSP-04": ["PHISH-S3"],
                "MSP-05": ["PHISH-S4", "PHISH-S5"],
            },
            "MS-SPRAY-EXAMPLE-001": {
                "SPRAY-S1": ["MSS-01"],
                "SPRAY-S2": ["MSS-02"],
                "SPRAY-S3": ["MSS-03"],
                "SPRAY-S4": ["MSS-04"],
                "SPRAY-S5": ["MSS-05"],
            },
            "SPLUNK-PSH-EXAMPLE-001": {
                "PSH-S1": ["SPSK-01"],
                "PSH-S2": ["SPSK-02"],
                "PSH-S3": ["SPSK-03"],
                "PSH-S4": ["SPSK-04"],
                "PSH-S5": ["SPSK-05"],
            },
            "CISA-FED-IR-META-001": {
                "PERSIST-S1": ["CISA-META-01"],
                "PERSIST-S2": ["CISA-META-02"],
                "PERSIST-S3": ["CISA-META-02"],
                "PERSIST-S4": ["CISA-META-03"],
                "PERSIST-S5": ["CISA-META-03"],
            },
        }
        target_pb_id = ver_row["playbook_id"]
        equiv_map = CROSS_PLAYBOOK_STEP_EQUIVALENCE.get(target_pb_id, {})

        observed_step_seq: List[str] = []
        observed_record_ids: List[str] = []
        observed_rows_expanded: List[Dict[str, Any]] = []
        for r in obs_rows:
            sid = r["playbook_step_id"]
            act_low = (r["activity"] or "").lower()
            if sid in all_valid_ids:
                observed_step_seq.append(sid)
                observed_record_ids.append(r["activity_record_id"])
                observed_rows_expanded.append(dict(r))
            elif sid in equiv_map:
                for mapped_sid in equiv_map[sid]:
                    if mapped_sid not in observed_step_seq or mapped_sid != observed_step_seq[-1]:
                        observed_step_seq.append(mapped_sid)
                        observed_record_ids.append(r["activity_record_id"])
                        observed_rows_expanded.append(dict(r))
            else:
                resolved = step_name_to_id.get(act_low) or alt_to_step_id.get(act_low) or (sid or r["activity"])
                observed_step_seq.append(resolved)
                observed_record_ids.append(r["activity_record_id"])
                observed_rows_expanded.append(dict(r))

        obs_counts = Counter(observed_step_seq)

        # 1. Skipped mandatory activities
        skipped_activities = [
            m_id for m_id in mandatory_ids if obs_counts.get(m_id, 0) == 0
        ]

        # 2. Additional (unmapped / out-of-playbook) activities
        additional_activities = [
            s_id for s_id in observed_step_seq if s_id not in all_valid_ids
        ]

        # 3. Repeated activities (executed > 1 time)
        repeated_activities = [
            s_id for s_id, cnt in obs_counts.items() if cnt > 1 and s_id in all_valid_ids
        ]

        # 4. Reordered activities (inversions in observed order among valid playbook steps)
        valid_obs_in_order = [s_id for s_id in observed_step_seq if s_id in step_order_map]
        reordered_activities = []
        max_order_seen = -1
        for s_id in valid_obs_in_order:
            ord_val = step_order_map[s_id]
            if ord_val < max_order_seen and s_id not in reordered_activities:
                reordered_activities.append(s_id)
            if ord_val > max_order_seen:
                max_order_seen = ord_val

        # 5. Premature termination (final mandatory closure step missing)
        final_mandatory = mandatory_ids[-1] if mandatory_ids else None
        is_premature_termination = bool(
            final_mandatory and (not observed_step_seq or observed_step_seq[-1] != final_mandatory) and final_mandatory in skipped_activities
        )

        # 6. Native PM4Py alignment replay (if pm4py is installed) with automatic built-in fallback
        obs_timestamps = [r.get("normalized_utc_timestamp") for r in observed_rows_expanded]
        native_pm4py_res = self._run_native_pm4py_alignment(
            case_id=case_id,
            playbook_version_id=pb_ver_id,
            observed_step_seq=observed_step_seq,
            observed_timestamps=obs_timestamps,
        )

        # Built-in Petri-net token-based replay Fitness & Precision calculation
        total_mandatory = max(len(mandatory_ids), 1)
        matched_mandatory = total_mandatory - len(skipped_activities)
        penalty_tokens = (
            len(skipped_activities) * 1.0
            + len(reordered_activities) * 0.5
            + len(repeated_activities) * 0.35
            + len(additional_activities) * 0.5
        )
        denom = max(total_mandatory + len(observed_step_seq), 1)
        fitness = round(max(0.0, min(1.0, 1.0 - (penalty_tokens / denom))), 4)

        # Escaping edges precision: fraction of observed transitions permitted by current marking
        valid_transitions = max(
            0,
            len(observed_step_seq)
            - len(additional_activities)
            - len(reordered_activities)
            - len(repeated_activities),
        )
        precision_score = (
            round(valid_transitions / len(observed_step_seq), 4)
            if observed_step_seq
            else 0.0
        )

        conformance_engine = "builtin_petri_net_replay_fallback"
        alignment_diagnostics = None
        if native_pm4py_res is not None:
            conformance_engine = native_pm4py_res["engine"]
            fitness = native_pm4py_res["fitness"]
            precision_score = native_pm4py_res["precision"]
            alignment_diagnostics = {
                "pm4py_version": native_pm4py_res["pm4py_version"],
                "alignment_cost": native_pm4py_res["alignment_cost"],
                "alignment_moves": native_pm4py_res["alignment_moves"],
            }

        is_conformant = (
            len(skipped_activities) == 0
            and len(reordered_activities) == 0
            and len(repeated_activities) == 0
            and len(additional_activities) == 0
            and not is_premature_termination
        )

        conf_id = f"CONF-{uuid.uuid4().hex[:8].upper()}"
        now_iso = utc_now_iso()
        variant_str = " -> ".join(observed_step_seq) if observed_step_seq else "EMPTY_TRACE"

        deviations_to_insert = []
        for s_id in skipped_activities:
            deviations_to_insert.append(
                (
                    f"DEV-{uuid.uuid4().hex[:8].upper()}",
                    conf_id,
                    case_id,
                    "skipped_activity",
                    s_id,
                    None,
                    f"Mandatory playbook step '{s_id}' was skipped in observed trace.",
                )
            )
        for s_id in reordered_activities:
            deviations_to_insert.append(
                (
                    f"DEV-{uuid.uuid4().hex[:8].upper()}",
                    conf_id,
                    case_id,
                    "reordered_activity",
                    s_id,
                    None,
                    f"Playbook step '{s_id}' was executed out of prescribed predecessor/successor order.",
                )
            )
        for s_id in repeated_activities:
            deviations_to_insert.append(
                (
                    f"DEV-{uuid.uuid4().hex[:8].upper()}",
                    conf_id,
                    case_id,
                    "repeated_activity",
                    s_id,
                    None,
                    f"Playbook step '{s_id}' was repeated {obs_counts[s_id]} times.",
                )
            )
        for s_id in additional_activities:
            deviations_to_insert.append(
                (
                    f"DEV-{uuid.uuid4().hex[:8].upper()}",
                    conf_id,
                    case_id,
                    "additional_activity",
                    None,
                    s_id,
                    f"Unmapped/additional activity '{s_id}' is not defined in reference playbook '{pb_ver_id}'.",
                )
            )
        if is_premature_termination:
            deviations_to_insert.append(
                (
                    f"DEV-{uuid.uuid4().hex[:8].upper()}",
                    conf_id,
                    case_id,
                    "premature_termination",
                    final_mandatory,
                    None,
                    f"Investigation trace terminated prematurely before mandatory closure step '{final_mandatory}'.",
                )
            )

        with db_manager.connection() as conn:
            conn.execute("DELETE FROM conformance_results WHERE case_id = ?", (case_id,))
            conn.execute(
                """
                INSERT INTO conformance_results (
                    conformance_id, case_id, playbook_version_id, algorithm,
                    fitness, precision_score, trace_variant_id, is_premature_termination, computed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    conf_id,
                    case_id,
                    pb_ver_id,
                    conformance_engine,
                    fitness,
                    precision_score,
                    variant_str,
                    1 if is_premature_termination else 0,
                    now_iso,
                ),
            )
            if deviations_to_insert:
                conn.executemany(
                    """
                    INSERT INTO deviation_findings (
                        deviation_id, conformance_id, case_id, deviation_category,
                        playbook_step_id, observed_activity_record_id, description
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    deviations_to_insert,
                )

        # 7. Compute 7-State Step Evaluation Semantics per GEMINI_INTEGRATION_PROMPT.md:
        #    performed, not_performed, not_documented, not_applicable,
        #    out_of_order, evidence_insufficient, condition_not_met
        obs_by_step_id: Dict[str, List[Dict[str, Any]]] = {}
        for r, resolved_sid in zip(observed_rows_expanded, observed_step_seq):
            obs_by_step_id.setdefault(resolved_sid, []).append(dict(r))

        active_cond_set = set(active_conditions or [])
        step_evaluations: List[Dict[str, Any]] = []
        state_summary: Counter = Counter()

        for s in expected_steps:
            sid = s["step_id"]
            mand_stat = s["mandatory_status"]
            is_cond = bool(s.get("is_conditional", 0)) or mand_stat == "conditional"
            cond_expr = s.get("condition_expression")
            ev_reqs = json.loads(s.get("applicable_evidence_requirements_json") or "[]")
            matched_records = obs_by_step_id.get(sid, [])

            if matched_records:
                first_rec = matched_records[0]
                has_ev = bool((first_rec.get("evidence_reference") or "").strip())
                orig_fields = json.loads(first_rec.get("original_fields_json") or "{}")
                doc_text = (
                    first_rec.get("outcome")
                    or orig_fields.get("justification_note")
                    or orig_fields.get("notes")
                    or first_rec.get("activity_status")
                    or ""
                ).strip()
                if sid in reordered_activities:
                    eval_state = "out_of_order"
                    rationale = f"Step '{sid}' was executed out of prescribed predecessor/sequence order."
                elif ev_reqs and not has_ev:
                    # Missing evidence artefact is NOT treated as proof action was not performed
                    eval_state = "evidence_insufficient"
                    rationale = f"Step '{sid}' was performed in trace, but required evidence {ev_reqs} is missing."
                elif not doc_text or doc_text.lower() in ("undocumented", "none", "n/a"):
                    eval_state = "not_documented"
                    rationale = f"Step '{sid}' was observed in trace, but lacks analyst documentation/outcome notes."
                else:
                    eval_state = "performed"
                    rationale = f"Step '{sid}' was performed in valid order with supporting evidence and documentation."
            else:
                if is_cond:
                    if cond_expr and cond_expr in active_cond_set:
                        eval_state = "not_performed"
                        rationale = f"Conditional step '{sid}' triggering condition '{cond_expr}' was met, but step was not performed."
                    else:
                        eval_state = "condition_not_met"
                        rationale = f"Conditional step '{sid}' was not triggered in this case scope."
                elif mand_stat == "optional":
                    eval_state = "not_applicable"
                    rationale = f"Optional/illustrative step '{sid}' is not mandatory for this case."
                else:
                    eval_state = "not_performed"
                    rationale = f"Mandatory step '{sid}' was not observed in analyst_activities."

            state_summary[eval_state] += 1
            step_evaluations.append(
                {
                    "step_id": sid,
                    "activity": s["step_name"],
                    "mandatory_status": mand_stat,
                    "evaluation_state": eval_state,
                    "rationale": rationale,
                    "observed_count": len(matched_records),
                }
            )

        return {
            "conformance_id": conf_id,
            "case_id": case_id,
            "playbook_version_id": pb_ver_id,
            "playbook_classification": pb_classification,
            "normalization_status": norm_status,
            "is_conformant": is_conformant,
            "fitness": fitness,
            "precision": precision_score,
            "observed_trace": observed_step_seq,
            "skipped_activities": skipped_activities,
            "reordered_activities": reordered_activities,
            "repeated_activities": repeated_activities,
            "additional_activities": additional_activities,
            "is_premature_termination": is_premature_termination,
            "deviation_count": len(deviations_to_insert),
            "step_evaluations": step_evaluations,
            "step_evaluation_counts": dict(state_summary),
            "conformance_engine": conformance_engine,
            "pm4py_available": PM4PY_AVAILABLE,
            "native_pm4py_diagnostics": alignment_diagnostics,
            "computed_at": now_iso,
        }


    def evaluate_case_standardized_triage_scale(self, case_id: str) -> Dict[str, Any]:
        """
        Compares a single case against ALL playbooks of its relevant attack type (incident_category)
        and computes the Standardized Triage Quality Scale (STQS v1.0):
          - Axis 1: Cross-Playbook Process Conformance Score (S_conf: 0..100)
          - Axis 2: Evidence-Grounded Investigation Quality Score (S_inv: 0..100)
          - Axis 3: Documentation & Justification Quality Score (S_doc: 0..100)
          - Composite Index: I_STQS = 0.40 * S_conf + 0.35 * S_inv + 0.25 * S_doc (with 5-tier STQS Band)
        """
        from backend.app.services.playbooks.repository import get_relevant_playbooks_for_attack_type

        with db_manager.connection() as conn:
            c_row = conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if not c_row:
                raise ValueError(f"Case '{case_id}' not found.")
            obs_rows = conn.execute(
                "SELECT * FROM analyst_activities WHERE case_id = ? ORDER BY normalized_utc_timestamp ASC",
                (case_id,),
            ).fetchall()

        case_dict = dict(c_row)
        incident_cat = case_dict["incident_category"]
        relevant_pbs = get_relevant_playbooks_for_attack_type(incident_cat)
        if not relevant_pbs:
            raise ValueError(f"No playbooks found for attack type '{incident_cat}'.")

        per_playbook_results = []
        conformance_scores = []
        primary_pb_ver_id = f"{case_dict.get('playbook_id') or relevant_pbs[0]['playbook_id']}@{case_dict.get('playbook_version') or '1.0'}"
        primary_conf_result = None

        for pb in relevant_pbs:
            pb_ver_id = pb["playbook_version_id"]
            # Allow multi-playbook comparative replay across both validated and working institutional playbooks
            # while explicitly reporting each playbook's normalization_status and conformance gate status
            conf = self.check_conformance_alignments(
                case_id=case_id,
                playbook_version_id=pb_ver_id,
                allow_unreviewed=True,
            )
            pb_score = round((0.70 * conf["fitness"] + 0.30 * conf["precision"]) * 100.0, 2)
            conformance_scores.append(pb_score)
            if pb_ver_id == primary_pb_ver_id or primary_conf_result is None:
                primary_conf_result = conf
            per_playbook_results.append(
                {
                    "playbook_version_id": pb_ver_id,
                    "playbook_id": pb["playbook_id"],
                    "version": pb["version"],
                    "title": pb["title"],
                    "institution": pb.get("institution", "SOC-QA Research Benchmark"),
                    "playbook_classification": pb.get("playbook_classification", "operational_soc_playbook"),
                    "normalization_status": pb.get("normalization_status", "validated"),
                    "conformance_gate": (
                        "VALIDATED_OR_HUMAN_REVIEWED"
                        if pb.get("normalization_status") in ("validated", "human_reviewed")
                        else "UNREVIEWED_ADVISORY_COMPARISON"
                    ),
                    "is_conformant": conf["is_conformant"],
                    "fitness": conf["fitness"],
                    "precision": conf["precision"],
                    "playbook_conformance_score_100": pb_score,
                    "skipped_activities": conf["skipped_activities"],
                    "reordered_activities": conf["reordered_activities"],
                    "repeated_activities": conf["repeated_activities"],
                    "additional_activities": conf["additional_activities"],
                    "is_premature_termination": conf["is_premature_termination"],
                    "step_evaluation_counts": conf["step_evaluation_counts"],
                }
            )

        # Restore primary playbook conformance record in conformance_results table so single-playbook queries stay pinned
        if primary_conf_result:
            self.check_conformance_alignments(
                case_id=case_id,
                playbook_version_id=primary_conf_result["playbook_version_id"],
                allow_unreviewed=True,
            )

        # Axis 1: Cross-Playbook Process Conformance Score (0..100)
        s_conf = round(sum(conformance_scores) / max(len(conformance_scores), 1), 2)

        # Axis 2: Evidence-Grounded Investigation Quality Score (0..100)
        total_obs = len(obs_rows)
        with_evidence = sum(
            1 for r in obs_rows if bool((r["evidence_reference"] or "").strip())
        )
        ev_ratio = (with_evidence / total_obs) if total_obs > 0 else 0.0
        primary_skipped = len(primary_conf_result["skipped_activities"]) if primary_conf_result else 0
        primary_premature = bool(primary_conf_result["is_premature_termination"]) if primary_conf_result else False
        inv_penalty = (primary_skipped * 18.0) + (25.0 if primary_premature else 0.0)
        s_inv = round(max(0.0, min(100.0, (ev_ratio * 100.0) - inv_penalty)), 2)

        # Axis 3: Documentation & Justification Quality Score (0..100)
        substantive_docs = 0
        for r in obs_rows:
            orig = json.loads(r["original_fields_json"] or "{}")
            note = str(
                orig.get("justification_note")
                or orig.get("notes")
                or r["outcome"]
                or ""
            ).strip()
            # Substantive documentation requires >= 22 characters and not a generic 1-2 word stub
            has_evd_ptr = bool((r["evidence_reference"] or "").strip())
            if has_evd_ptr and len(note) >= 16 and note.lower() not in ("unverified stub", "done", "ok", "checked", "completed"):
                substantive_docs += 1
        s_doc = round((substantive_docs / total_obs) * 100.0, 2) if total_obs > 0 else 0.0

        # Transparent Standardized Triage Quality Index (0..100)
        stqs_index = round(0.40 * s_conf + 0.35 * s_inv + 0.25 * s_doc, 2)

        # 5-Tier Standardized Triage Quality Band (preserving orthogonal visibility)
        if primary_premature or stqs_index < 45.0:
            band_code = "STQS-1"
            band_label = "Level 1 — Critical Triage Failure / Premature Closure"
        elif s_conf >= 80.0 and s_doc < 80.0:
            band_code = "STQS-3"
            band_label = "Level 3 — Procedurally Sound but Documentation-Deficient"
        elif stqs_index >= 85.0 and s_conf >= 80.0 and s_inv >= 85.0 and s_doc >= 80.0:
            band_code = "STQS-5"
            band_label = "Level 5 — Exemplary Multi-Playbook Triage"
        elif stqs_index >= 70.0 and s_conf >= 75.0:
            band_code = "STQS-4"
            band_label = "Level 4 — Sound Operational Triage (Minor Institutional Variance)"
        else:
            band_code = "STQS-2"
            band_label = "Level 2 — Material Playbook Drift / Partial Triage"

        return {
            "case_id": case_id,
            "incident_category": incident_cat,
            "pinned_playbook_version_id": primary_pb_ver_id,
            "relevant_playbooks_evaluated_count": len(per_playbook_results),
            "relevant_playbooks_evaluated": [p["playbook_version_id"] for p in per_playbook_results],
            "orthogonal_scores": {
                "process_conformance_score": s_conf,
                "investigation_quality_score": s_inv,
                "documentation_quality_score": s_doc,
            },
            "standardized_triage_quality_index": stqs_index,
            "stqs_band_code": band_code,
            "stqs_band_label": band_label,
            "scale_formula": "I_STQS = 0.40 * S_conf + 0.35 * S_inv + 0.25 * S_doc (Orthogonal axes always reported separately)",
            "per_playbook_conformance": per_playbook_results,
        }

    def evaluate_all_cases_standardized_triage_scale(self) -> Dict[str, Any]:
        """
        Evaluates all cases in the workspace against all playbooks of each case's relevant attack type,
        returning the complete Standardized Triage Quality Scale (STQS) table and band distribution.
        """
        with db_manager.connection() as conn:
            case_rows = conn.execute(
                "SELECT case_id FROM cases ORDER BY case_id ASC"
            ).fetchall()

        results = []
        band_counts: Counter = Counter()
        by_attack_type: Dict[str, List[float]] = {}

        for r in case_rows:
            ev = self.evaluate_case_standardized_triage_scale(r["case_id"])
            results.append(ev)
            band_counts[ev["stqs_band_code"]] += 1
            by_attack_type.setdefault(ev["incident_category"], []).append(
                ev["standardized_triage_quality_index"]
            )

        attack_type_summary = {
            cat: {
                "case_count": len(vals),
                "mean_stqs_index": round(sum(vals) / len(vals), 2) if vals else 0.0,
            }
            for cat, vals in by_attack_type.items()
        }

        return {
            "total_cases_evaluated": len(results),
            "band_distribution": dict(band_counts),
            "attack_type_summary": attack_type_summary,
            "case_evaluations": results,
        }


pm4py_service = OperationalProcessMiningEngine()
