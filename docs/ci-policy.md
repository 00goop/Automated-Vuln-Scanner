# CI and security policy

Tests/build runs offline behavior tests and frontend lint/build. The scheduled workflow ingests NVD data and saves a clearly named synthetic experiment. Fetch errors and empty datasets fail; no previous model is silently substituted and no experiment is promoted.

Deploy Guard fails on every dependency advisory reported by pip-audit, any high-severity Bandit finding, or an operational scanner error. Lower-severity source findings are informational and should be reviewed separately. Reports and outcomes are retained on failure. There is no severity guessing from arbitrary dependency JSON or swallowed error fallback.

The check alone does not block external deployment: branch protection and the host must require successful checks. This repository does not establish that integration. An arbitrary synthetic F1 threshold is intentionally not a release gate.
