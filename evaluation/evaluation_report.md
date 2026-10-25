\# Evaluation Report



\## Overview



The Ghost Data Audit agent independently evaluates deletion requests using historical evidence available at the audit timestamp.



The pipeline processes each deletion case through:



1\. Evidence analysis

2\. Identity resolution

3\. State reconstruction

4\. Status determination

5\. Remediation planning

6\. Validation



\## Dataset Results



\- Total deletion cases: 518

\- Cases processed successfully: 518

\- Runtime errors: 0

\- UNKNOWN state cases: 0

\- Validator-valid cases: 518

\- Validator-invalid cases: 0



\## Reconstructed Status



| Status | Cases |

|---|---:|

| COMPLETE | 156 |

| INCOMPLETE | 362 |



\## Reported vs Reconstructed Status



The source deletion requests reported:



| Reported Status | Cases |

|---|---:|

| COMPLETE | 254 |

| PARTIALLY\_COMPLETE | 152 |

| NOT\_STARTED | 112 |



The agent independently reconstructed the actual state from evidence rather than relying on the reported status.



Reported and reconstructed status differed for 433 of 518 cases.



\## Remediation Planning



The agent generated 3,138 remediation and verification steps across the processed cases.



Blocking states include:



\- PRESENT

\- EXPOSED\_PII

\- RESTORE\_RISK



Non-blocking states include:



\- OBSERVATION

\- IDENTITY\_LINK

\- RETAINED



UNKNOWN states are treated as incomplete until deterministically resolved.



\## Validation



All 518 generated case results passed the independent validator.



Validation checks included:



\- Required result fields

\- Valid status values

\- State-summary consistency

\- Blocking-state consistency

\- Step numbering

\- Valid remediation phases

\- Required identifiers



Final validation result:



\*\*518 / 518 valid cases\*\*

