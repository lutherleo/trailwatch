| overrides | recall | precision | alerts | false alerts/day |
|---|---:|---:|---:|---:|
| {'scoring.half_life_hours': 3, 'scoring.threshold': 40} | 0.833 | 0.876 | 97 | 0.044 |
| {'scoring.half_life_hours': 3, 'scoring.threshold': 50} | 0.833 | 0.897 | 97 | 0.037 |
| {'scoring.half_life_hours': 3, 'scoring.threshold': 60} **(best)** | 0.833 | 0.899 | 89 | 0.033 |
| {'scoring.half_life_hours': 3, 'scoring.threshold': 75} **(best)** | 0.833 | 0.899 | 89 | 0.033 |
| {'scoring.half_life_hours': 3, 'scoring.threshold': 90} **(best)** | 0.833 | 0.899 | 89 | 0.033 |
| {'scoring.half_life_hours': 6, 'scoring.threshold': 40} | 0.833 | 0.869 | 99 | 0.048 |
| {'scoring.half_life_hours': 6, 'scoring.threshold': 50} | 0.833 | 0.888 | 98 | 0.041 |
| {'scoring.half_life_hours': 6, 'scoring.threshold': 60} **(best)** | 0.833 | 0.899 | 89 | 0.033 |
| {'scoring.half_life_hours': 6, 'scoring.threshold': 75} **(best)** | 0.833 | 0.899 | 89 | 0.033 |
| {'scoring.half_life_hours': 6, 'scoring.threshold': 90} **(best)** | 0.833 | 0.899 | 89 | 0.033 |
| {'scoring.half_life_hours': 12, 'scoring.threshold': 40} | 0.833 | 0.833 | 102 | 0.063 |
| {'scoring.half_life_hours': 12, 'scoring.threshold': 50} | 0.833 | 0.853 | 102 | 0.056 |
| {'scoring.half_life_hours': 12, 'scoring.threshold': 60} | 0.833 | 0.880 | 92 | 0.041 |
| {'scoring.half_life_hours': 12, 'scoring.threshold': 75} **(best)** | 0.833 | 0.899 | 89 | 0.033 |
| {'scoring.half_life_hours': 12, 'scoring.threshold': 90} **(best)** | 0.833 | 0.899 | 89 | 0.033 |

best within 0.05 false alerts/day (8 tied):
  {'scoring.half_life_hours': 3, 'scoring.threshold': 60}
  {'scoring.half_life_hours': 3, 'scoring.threshold': 75}
  {'scoring.half_life_hours': 3, 'scoring.threshold': 90}
  {'scoring.half_life_hours': 6, 'scoring.threshold': 60}
  {'scoring.half_life_hours': 6, 'scoring.threshold': 75}
  {'scoring.half_life_hours': 6, 'scoring.threshold': 90}
  {'scoring.half_life_hours': 12, 'scoring.threshold': 75}
  {'scoring.half_life_hours': 12, 'scoring.threshold': 90}
