held-out seeds [1001, 1002, 1003, 1004, 1005], 90 days each

| variant | incidents | detected | recall | alerts | precision | alerts/day | false alerts/day | median TTD (min) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full | 60 | 50 | 0.833 | 158 | 0.867 | 0.351 | 0.047 | 0.0 |
| no_familiarity_suppression | 60 | 50 | 0.833 | 2531 | 0.060 | 5.624 | 5.289 | 0.0 |
| no_behavioral_novelty | 60 | 45 | 0.750 | 107 | 0.878 | 0.238 | 0.029 | 0.0 |
| no_risk_scoring | 60 | 47 | 0.783 | 141 | 0.929 | 0.313 | 0.022 | 0.0 |

## full

| variant | incidents | detected | recall | alerts | precision | alerts/day | false alerts/day | median TTD (min) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full | 60 | 50 | 0.833 | 158 | 0.867 | 0.351 | 0.047 | 0.0 |

| scenario | recall |
|---|---:|
| access_key_persistence | 1.000 |
| console_no_mfa_privesc | 1.000 |
| defense_evasion | 1.000 |
| low_and_slow | 0.000 |
| recon_burst | 1.000 |
| stolen_access_key | 1.000 |

false alerts by rule: {'console_no_mfa_iam_change': 8, 'logging_disabled': 2, 'risk_threshold': 11}
events/s: 30058
