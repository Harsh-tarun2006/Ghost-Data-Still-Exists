# Ghost Data Still Exists

## AI-Powered Data Audit & Remediation Pipeline

A deterministic, evidence-driven pipeline designed to detect **ghost data** — records that may continue to exist across distributed systems even after deletion, removal, or lifecycle actions were expected to occur.

The system analyzes evidence from multiple sources, resolves identities, reconstructs entity state, determines the current status of each case, and generates actionable remediation steps.

---

## 1. Problem Statement

In distributed systems, deleting a record from one system does not necessarily mean that all traces of that record have disappeared.

Residual data may continue to exist in:

- Service databases
- Customer systems
- System activity records
- Audit logs
- Backups or retained records
- Other connected systems

This creates an important auditing problem:

> **How can we determine whether a record was actually removed, whether evidence of its existence still remains, and what remediation actions are required?**

This project addresses that problem through an automated evidence-analysis and remediation pipeline.

---

## 2. What the System Does

The pipeline processes audit cases and performs the following operations:

1. **Evidence Analysis**
   - Reads and parses evidence from multiple sources.
   - Extracts relevant facts related to deletion, retention, and lifecycle events.
   - Identifies evidence relevant to each audit case.

2. **Identity Resolution**
   - Determines which pieces of evidence belong to the same logical entity.
   - Connects identities across different systems and evidence sources.

3. **State Reconstruction**
   - Reconstructs the lifecycle and current state of an entity.
   - Uses historical and current evidence to determine what happened before and after relevant events.

4. **Policy Evaluation**
   - Applies the available deletion and lifecycle rules.
   - Determines whether the observed state satisfies the expected policy conditions.

5. **Status Determination**
   - Converts the reconstructed state and policy results into a standardized case status.

6. **Remediation Planning**
   - Generates required remediation actions for incomplete or unresolved states.
   - Produces actionable steps rather than simply reporting a problem.

7. **Batch Processing**
   - Processes the complete dataset of **518 audit cases**.

8. **Validation & Evaluation**
   - Validates the generated results.
   - Produces evaluation and usage reports.

---

## 3. System Pipeline

```text
Evidence Sources
       |
       v
Evidence Retrieval / Parsing
       |
       v
Evidence Analysis
       |
       v
Identity Resolution
       |
       v
State Reconstruction
       |
       v
Policy Evaluation
       |
       v
Status Engine
       |
       v
Remediation Planner
       |
       v
Output Generation
       |
       v
Batch Validation
       |
       v
Evaluation & Usage Reports
```

The pipeline follows a structured, evidence-driven approach where each stage consumes information produced or organized by the previous stages.

---

## 4. Project Structure

```text
ghost-data-audit/
│
├── agent/
│   ├── case_runner.py
│   ├── evidence_analyzer.py
│   ├── evidence_parser.py
│   ├── evidence_retriever.py
│   ├── identity_resolver.py
│   ├── policy_engine.py
│   ├── remediation_planner.py
│   ├── state_reconstructor.py
│   ├── status_engine.py
│   └── validator.py
│
├── dataset/
│   ├── deletion_requests.csv
│   ├── deletion_rules.csv
│   ├── evidence/
│   ├── evidence_files.csv
│   ├── system_activity.csv
│   ├── user_audit_log.csv
│   └── user_identities.csv
│
├── evaluation/
│   ├── evaluation_report.md
│   └── usage_report.md
│
├── prompts/
│   └── evidence_analysis.txt
│
├── generate_output.py
├── output.csv
├── requirements.txt
├── README.md
└── validate_batch.py
```

> `venv/` and Python-generated `__pycache__/` directories are local/generated artifacts and should not be committed to the repository.

---

## 5. Dataset

The `dataset/` directory contains the input data and supporting evidence used by the pipeline.

### Input files

| File | Purpose |
|---|---|
| `deletion_requests.csv` | Deletion requests and related case information |
| `deletion_rules.csv` | Rules used for deletion/lifecycle evaluation |
| `evidence_files.csv` | Evidence-file metadata and references |
| `system_activity.csv` | System activity associated with entities |
| `user_audit_log.csv` | Audit events and historical activity |
| `user_identities.csv` | Identity information used for cross-system resolution |
| `evidence/` | Supporting evidence files |

The evidence from these sources is combined to reconstruct the most defensible state for each audit case.

---

## 6. Evidence Analysis

The evidence-processing layer is implemented through several components under `agent/`.

### `evidence_retriever.py`

Retrieves the evidence required for processing individual cases.

### `evidence_parser.py`

Parses evidence into a structured representation that can be consumed by later stages.

### `evidence_analyzer.py`

Analyzes the structured evidence and extracts relevant facts for state reconstruction and decision-making.

The project also contains:

```text
prompts/evidence_analysis.txt
```

which contains the prompt/template used for the evidence-analysis component.

---

## 7. Core Processing Components

### Case Runner

```text
agent/case_runner.py
```

Coordinates case-level processing through the pipeline.

### Evidence Analyzer

```text
agent/evidence_analyzer.py
```

Extracts and organizes useful information from available evidence.

### Identity Resolver

```text
agent/identity_resolver.py
```

Connects evidence belonging to the same logical entity across different systems.

### State Reconstructor

```text
agent/state_reconstructor.py
```

Combines historical and current evidence to reconstruct the lifecycle state of an entity.

### Policy Engine

```text
agent/policy_engine.py
```

Applies the relevant deletion and lifecycle rules to the reconstructed state.

### Status Engine

```text
agent/status_engine.py
```

Determines the standardized status of each case.

### Remediation Planner

```text
agent/remediation_planner.py
```

Determines the actions required to resolve incomplete or non-compliant states.

### Validator

```text
agent/validator.py
```

Provides validation logic used during the processing pipeline.

---

## 8. Output

The main generated result is:

```text
output.csv
```

The output contains the processed result for each audit case, including the determined status and remediation information.

The project also contains supporting evaluation artifacts under:

```text
evaluation/
```

including:

```text
evaluation_report.md
usage_report.md
```

---

## 9. Processing Results

The complete dataset contains:

```text
Total cases processed: 518
Valid cases:            518
Validation warnings:      0
```

### Status Distribution

| Status | Cases |
|---|---:|
| COMPLETE | 254 |
| PARTIALLY_COMPLETE | 152 |
| NOT_STARTED | 112 |
| **Total** | **518** |

The remediation planner generated:

```text
Total remediation steps: 3,138
Unknown / invalid remediation steps: 0
```

These results demonstrate successful processing of the complete batch with no invalid generated remediation steps.

---

## 10. Validation

The generated output is validated through:

```text
validate_batch.py
```

Final validation result:

```text
Cases processed:     518
Valid cases:         518
Warnings:              0
```

The validation stage provides an additional verification layer before the output is considered ready for submission.

---

## 11. Evaluation

Evaluation artifacts are stored under:

```text
evaluation/
```

### `evaluation_report.md`

Contains the final evaluation and processing results.

### `usage_report.md`

Documents system usage and related execution information.

---

## 12. Running the Project

### Step 1 — Activate the virtual environment

Because this project is being run on Windows Command Prompt:

```cmd
venv\Scripts\activate
```

### Step 2 — Install dependencies

```cmd
pip install -r requirements.txt
```

### Step 3 — Generate the output

```cmd
python generate_output.py
```

This runs the processing pipeline and generates:

```text
output.csv
```

### Step 4 — Validate the output

```cmd
python validate_batch.py
```

The validator checks the generated batch output for the expected structural and logical constraints.

---

## 13. Design Principles

### Evidence First

Decisions are based on available evidence rather than assumptions.

### Deterministic Processing

The pipeline follows a predictable and reproducible sequence of processing stages.

### Traceable Decisions

The modular architecture makes it possible to understand how evidence contributes to the final case status.

### Policy-Aware Decisions

Deletion and lifecycle rules are explicitly considered during case evaluation.

### Actionable Results

The system does not stop at identifying incomplete cases; it also generates remediation actions.

### Batch Reliability

The complete dataset is processed and validated before the final output is considered ready.

---

## 14. Final System Flow

```text
Raw Evidence
     |
     v
Evidence Retrieval & Parsing
     |
     v
Evidence Analysis
     |
     v
Identity Resolution
     |
     v
State Reconstruction
     |
     v
Policy Evaluation
     |
     v
Status Classification
     |
     v
Remediation Planning
     |
     v
518 Cases Processed
     |
     v
output.csv
     |
     v
Validation
     |
     v
Evaluation Reports
```

---

## 15. Current Project Status

The core processing pipeline is complete.

### Completed

- Evidence retrieval
- Evidence parsing
- Evidence analysis
- Identity resolution
- State reconstruction
- Policy evaluation
- Status determination
- Remediation planning
- Batch processing
- Output generation
- Output validation
- Evaluation report
- Usage report

### Final Validation

```text
518 / 518 cases valid
0 warnings
3,138 remediation steps
0 unknown remediation steps
```

---

## 16. Conclusion

**Ghost Data Still Exists** demonstrates an automated approach for auditing distributed data lifecycle states.

Instead of checking whether a record exists in only one location, the system combines evidence from multiple sources, resolves identities, reconstructs the entity state, applies relevant policies, determines the current status, and generates remediation actions.

The result is a complete, validated, and actionable audit pipeline capable of processing the full **518-case dataset**.