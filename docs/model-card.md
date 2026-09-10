# Vulnerability prioritization model card

This is an educational ranking experiment, not a validated predictor of exploitation. Do not use it as the sole basis for security decisions. Low scores do not establish safety; scores are not calibrated probabilities.

## Dataset and target

NVD ingestion produces normalized CVEs. Training requires explicit labels. `--synthetic` generates seeded Bernoulli labels from CVSS/10 solely for an experiment. Metrics record label provenance, dataset SHA-256, seed, class distribution and fixed feature observation date. The scheduled workflow saves experiment artifacts separately and never promotes them to the serving model directory.

`--labels` accepts a JSON mapping of CVE IDs to external binary labels. This does not validate their provenance. A real study needs a source, observation window, licensing review, inclusion criteria and justified negative labels before results support a real-world claim.

## Features and leakage

The model uses exploitability/impact scores, attack complexity, confidentiality/integrity/availability impacts, publication age, reference count and affected-product count. It excludes known-exploit status and all inputs used by the previous synthetic target, including CVSS base score. Related CVSS fields remain correlated with the synthetic target: even a high F1 measures reconstruction of an artificial task. Current NVD features can contain post-outcome information; real-label work requires frozen historical snapshots and temporal splits.

## Training and evaluation

Seeded Random Forest (100 trees, maximum depth 10, minimum leaf size 2, balanced classes), stratified 80/20 holdout and most-frequent-class baseline. Scaling fits training data only. No tuning on the holdout. Metrics include F1, precision, recall, confusion matrix and sample/class counts. No measured value is hard-coded into this card. Duplicate CVE IDs and malformed records are rejected before labels can become misaligned.

```bash
cd backend
python -m pip install -r requirements-ml.txt
python -m ml.trainer --data data/cves.json --synthetic --model-dir experiments/local
```

Dataset `fetched_at` fixes age features. Use the same dataset and pinned dependencies when comparing runs. Only load trusted joblib files; deserialization can execute code. Old 17-feature artifacts must be retrained.

## Real-label next step

Investigate CISA's Known Exploited Vulnerabilities catalog with a dated snapshot and review its terms. Membership indicates known exploitation; absence does not establish non-exploitation. Do not turn absent CVEs into verified negative labels. Prospective validation and calibration remain outstanding.

Source for the proposed real-label investigation: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Absence-as-negative is a methodological limitation, not a claim made by the catalog.
