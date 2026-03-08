import warnings; warnings.filterwarnings("ignore")
from pathlib import Path
from product.score_enriched_cves import score_endpoint, _find_model_path

enriched_path = Path("product/output/product_cve_enriched_test.json")
output_path = Path("product/output/product_cve_scored_test.json")
model_path = _find_model_path("xgboost_model_v4_calibrated.pkl")
encoder_path = _find_model_path("onehot_encoder_v4.pkl")

scored, summary = score_endpoint(enriched_path, model_path, encoder_path, output_path)
tier = summary["tier_counts"]
print(f"Scored {summary['total_cves_scored']} CVEs")
print(f"Tiers: C={tier.get('CRITICAL',0)} H={tier.get('HIGH',0)} M={tier.get('MODERATE',0)} L={tier.get('LOW',0)}")
for name, count, risk, top in summary["per_product"]:
    print(f"  {name:50s} {count:3d} CVEs  max_risk={risk:.4f} ({risk*100:.1f}/100)  tier={top}")

# Show individual CVE scores
import json
data = json.load(open(output_path))
for entry in data:
    pn = entry.get("product_normalized", "")
    dn = entry.get("display_product", pn)
    for cve in entry.get("matched_cves", []):
        cid = cve.get("cve_id")
        ml = cve.get("ml_exploit_probability", 0)
        cvss_n = cve.get("cvss_severity_norm", 0)
        epss = cve.get("epss", 0)
        risk = cve.get("final_cve_risk", 0)
        risk100 = cve.get("final_cve_risk_0_100", 0)
        tier_str = cve.get("risk_tier", "?")
        print(f"    {cid:18s}  {dn:40s}  ml={ml:.4f} cvss_n={cvss_n:.2f} epss={epss:.4f} risk={risk100:6.2f}/100 [{tier_str}]")
