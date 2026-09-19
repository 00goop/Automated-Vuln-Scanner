# Scanner modernization plan

## Findings

Both workflows point at absent directories. Scheduled evaluation does not save the files it uploads. Security failures are swallowed. Synthetic labels are unseeded and depend on prediction inputs. Feature extraction replaces legitimate zero CVSS values and can silently discard malformed rows, misaligning labels. README and inference text overstate exploitation prediction. No tests exist.

## Intended changes and affected files

Repair `.github/workflows/`, `backend/data/nvd_fetcher.py`, `backend/ml/` and add behavioral tests. Keep the API/frontend architecture. Add model/CI documentation and update claims. Review frontend build/lint and request validation after model checks pass.

## Risks

Feature schema changes invalidate old serialized artifacts: regenerate models. Synthetic experiments cannot support real-world exploitation claims. Online ingestion/security audits can fail due to provider availability and must report failure honestly. No production model promotion or deployment is performed.

## Acceptance and progress

- [x] Inspect entry points, manifests, current workflows and ML data path.
- [~] Repair workflow execution and explicit synthetic artifacts.
- [ ] Add deterministic training, baseline, dataset validation and model card.
- [ ] Test missing fields, malformed input, empty data, zero CVSS, save/load and inference.
- [ ] Verify frontend and security checks; document unresolved findings.
- [ ] Publish a reviewable branch and pull request linked to issue #2.

## Verified 2026-09-10
- [x] 13 behavioral tests pass with pinned ML dependencies.
- [x] Frontend lint and production build pass (native config loader used for Windows sandbox).
- [x] Python dependency audit and npm audit report no known advisories after repairs.
- [x] High-severity Bandit scan passes; actual failures remain enforced.
- [x] Desktop and 390px mobile browser inspection; offline notice verified without synthetic dashboard data.
- [ ] GitHub-hosted CI verification and full online NVD/provider checks remain pending.
