"""Deterministic CVE matching for one endpoint inventory.

Goal
----
Map installed products (already normalized) to relevant CVEs using a high-precision,
fully automatic, deterministic two-stage pipeline:

Stage 1 — Candidate generation
  - Prefer structured NVD configuration / CPE evidence.
  - Only fall back to text evidence when structured CPE/config evidence is absent.

Stage 2 — Candidate validation
  - Vendor/product consistency checks.
  - Collision filtering (reject CVEs that likely belong to sibling products).
  - Version relevance filtering (structured version bounds first, then conservative text heuristics).

This script intentionally does NOT:
- call any ML model
- compute risk scores
- modify input files

Inputs
------
1) Installed inventory (one endpoint)
   Default: product/output/product_inventory.json

2) NVD dataset (local)
   Searches in order:
   1) nvd_cves_all.json
   2) data/nvd_cves_all.json
   3) nvd/nvd_cves_all.json

Output
------
Writes: product/output/product_cve_matches.json

Run
---
  python product/map_products_to_cves.py

  # Or specify inventory explicitly
  python product/map_products_to_cves.py --inventory product/output/output_inventory.json

"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


# ----------------------------
# Utilities
# ----------------------------


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _json_default(obj: Any) -> Any:
    # ijson may parse numbers as Decimal for precision. Convert to JSON-safe primitives.
    try:
        from decimal import Decimal

        if isinstance(obj, Decimal):
            # Preserve integers as ints when possible.
            if obj == obj.to_integral_value():
                return int(obj)
            return float(obj)
    except Exception:
        pass
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def _write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=_json_default)
        f.write("\n")


def _norm_space(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _tokenize_words(s: str) -> List[str]:
    """Tokenize into conservative word tokens (letters/numbers)."""
    return re.findall(r"[a-z0-9]+", s.lower())


def _parse_version_tuple(v: Optional[str]) -> Optional[Tuple[int, ...]]:
    """Parse dotted numeric version into an integer tuple.

    Examples:
      147.0.4 -> (147,0,4)
      7.2.2.170484 -> (7,2,2,170484)

    Ignores non-numeric suffixes.
    Returns None if not parseable.
    """
    if not v:
        return None
    v = v.strip()
    if not v or v.lower() in {"unknown", "n/a", "na", "none"}:
        return None
    parts = []
    for chunk in v.split("."):
        m = re.match(r"^(\d+)", chunk)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts) if parts else None


def _compare_versions(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """Return -1/0/+1 comparing two version tuples with zero-padding."""
    n = max(len(a), len(b))
    ap = a + (0,) * (n - len(a))
    bp = b + (0,) * (n - len(b))
    if ap < bp:
        return -1
    if ap > bp:
        return 1
    return 0


# ----------------------------
# Inventory parsing
# ----------------------------


@dataclass(frozen=True)
class ProductProfile:
    display_product: str
    vendor_normalized: str
    product_normalized: str
    product_family: str
    version_normalized: Optional[str]
    mapping_candidates: List[Dict[str, str]]

    strong_phrases: List[str]
    vendor_tokens: Set[str]


def _build_product_profile(rec: Dict[str, Any]) -> ProductProfile:
    display_product = str(rec.get("display_product") or rec.get("product_normalized") or "").strip()
    vendor = str(rec.get("vendor_normalized") or "unknown").strip().lower()
    product_norm = str(rec.get("product_normalized") or "unknown_product").strip().lower()
    family = str(rec.get("product_family") or product_norm).strip().lower()
    version = rec.get("version_normalized")
    version_str = str(version).strip() if isinstance(version, str) else None

    mapping_candidates = rec.get("mapping_candidates") or []
    if not isinstance(mapping_candidates, list):
        mapping_candidates = []

    # Strong product phrases:
    # - display name
    # - product_normalized core
    # - product_family
    # - mapping candidate products
    phrases: Set[str] = set()

    def add_phrase(p: str) -> None:
        p = _norm_space(p)
        if not p:
            return
        # Avoid overly generic single-token phrases.
        words = _tokenize_words(p)
        if len(words) == 1 and words[0] in {"code", "browser", "runtime", "service", "update", "tool", "tools"}:
            return
        phrases.add(p)

    add_phrase(display_product)
    add_phrase(product_norm.replace("_", " "))
    add_phrase(family.replace("_", " "))

    for mc in mapping_candidates:
        if not isinstance(mc, dict):
            continue
        p = str(mc.get("product") or "")
        add_phrase(p.replace("_", " "))

    # Vendor tokens.
    vendor_tokens = {vendor}
    # Add normalized vendor words too (e.g., python_software_foundation).
    for t in vendor.split("_"):
        if t:
            vendor_tokens.add(t)

    # Include vendors from mapping candidates (for CPE alias matching).
    for mc in mapping_candidates:
        if isinstance(mc, dict):
            mc_vendor = str(mc.get("vendor") or "").strip().lower()
            if mc_vendor:
                vendor_tokens.add(mc_vendor)

    # Prefer longer phrases first for matching.
    strong_phrases = sorted(phrases, key=lambda x: (-len(x), x))

    return ProductProfile(
        display_product=display_product,
        vendor_normalized=vendor,
        product_normalized=product_norm,
        product_family=family,
        version_normalized=version_str,
        mapping_candidates=mapping_candidates,
        strong_phrases=strong_phrases,
        vendor_tokens=vendor_tokens,
    )


def _load_inventory(path: str) -> List[Dict[str, Any]]:
    inventory = _read_json(path)
    if not isinstance(inventory, list):
        raise ValueError(f"Inventory must be a JSON array: {path}")
    return [x for x in inventory if isinstance(x, dict)]


def _should_skip_product(profile: ProductProfile) -> Tuple[bool, Optional[str]]:
    """Deterministically skip clearly non-actionable products."""
    p = profile.product_normalized
    d = _norm_space(profile.display_product)

    # Windows KB updates / update helpers are not meaningful standalone CVE targets here.
    if re.search(r"\bkb\d{5,8}\b", d):
        return True, "system update component"
    if p.startswith("microsoft_update_") or "update_health" in p:
        return True, "system update component"

    # Maintenance / helper services (often bundled with a main product).
    if "maintenance service" in d or p.endswith("maintenance_service"):
        return True, "helper/maintenance component"

    # Generic uninstall helpers.
    if "uninstall" in d:
        return True, "uninstall helper"

    return False, None


# ----------------------------
# NVD parsing
# ----------------------------


@dataclass(frozen=True)
class CpeMatchEvidence:
    criteria: str
    cpe_part: Optional[str]
    cpe_vendor: Optional[str]
    cpe_product: Optional[str]
    cpe_version: Optional[str]
    cpe_target_sw: Optional[str]
    version_start_including: Optional[str]
    version_start_excluding: Optional[str]
    version_end_including: Optional[str]
    version_end_excluding: Optional[str]


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    published: Optional[str]
    description: str
    cwe: Optional[str]
    cvss_v3: Optional[Dict[str, Any]]
    references: List[str]

    has_cpe_evidence: bool
    cpe_matches: List[CpeMatchEvidence]


_CPE_RE = re.compile(r"^cpe:2\.3:[aho]:(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*):")


def _parse_cpe_23_full(criteria: str) -> Dict[str, Optional[str]]:
    """Parse a CPE 2.3 URI into key fields used for deterministic filtering.

    CPE 2.3 format:
      cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>

    We primarily use vendor/product/version and target_sw for platform filtering.
    """

    if not criteria or not isinstance(criteria, str):
        return {"part": None, "vendor": None, "product": None, "version": None, "target_sw": None}

    s = criteria.strip()
    if not s.startswith("cpe:2.3:"):
        return {"part": None, "vendor": None, "product": None, "version": None, "target_sw": None}

    parts = s.split(":")
    # Expect at least 13 components: 'cpe','2.3', part + 10 fields
    if len(parts) < 13:
        return {"part": None, "vendor": None, "product": None, "version": None, "target_sw": None}

    cpe_part = parts[2].strip().lower() or None
    vendor = parts[3].strip().lower() or None
    product = parts[4].strip().lower() or None
    version = parts[5].strip().lower() or None
    target_sw = parts[10].strip().lower() or None

    return {"part": cpe_part, "vendor": vendor, "product": product, "version": version, "target_sw": target_sw}


def _parse_cpe_23(criteria: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    m = _CPE_RE.match(criteria or "")
    if not m:
        return None, None, None
    vendor = m.group("vendor").strip().lower() or None
    product = m.group("product").strip().lower() or None
    version = m.group("version").strip().lower() or None
    return vendor, product, version


def _infer_endpoint_platform(inventory: List[Dict[str, Any]]) -> str:
    """Infer endpoint platform from inventory install locations.

    Deterministic heuristic:
    - Windows paths often contain drive letters (C:\\) or backslashes.
    - macOS often uses /Applications
    - Linux often uses /usr, /opt, /var
    """

    locations: List[str] = []
    for r in inventory:
        loc = r.get("install_location")
        if isinstance(loc, str) and loc and loc.lower() not in {"unknown", "n/a", "na"}:
            locations.append(loc)

    for loc in locations:
        # Accept both Windows separators (\\) and slash-normalized paths (C:/...).
        if re.match(r"^[a-zA-Z]:[\\/]", loc) or "\\" in loc:
            return "windows"
    for loc in locations:
        if loc.startswith("/Applications"):
            return "macos"
    for loc in locations:
        if loc.startswith("/usr") or loc.startswith("/opt") or loc.startswith("/var"):
            return "linux"

    return "unknown"


def _platform_allows_cpe_target_sw(endpoint_platform: str, target_sw: Optional[str]) -> bool:
    """Return True if a CPE target_sw is compatible with the endpoint platform.

    This prevents false positives like Firefox-for-iOS CVEs matching desktop Firefox.
    """

    if not endpoint_platform or endpoint_platform == "unknown":
        return True

    tsw = (target_sw or "").strip().lower()
    if tsw in {"", "*", "-"}:
        return True

    # Mobile platforms
    if tsw in {"iphone_os", "ios", "ipad_os", "ipados", "android"}:
        return endpoint_platform in {"ios", "android"}

    # Desktop platforms
    if tsw in {"windows", "microsoft_windows", "win32"}:
        return endpoint_platform == "windows"
    if tsw in {"mac_os", "macos", "osx"}:
        return endpoint_platform == "macos"
    if tsw in {"linux"}:
        return endpoint_platform == "linux"

    # If it's some other target_sw token, keep it (conservative).
    return True


def _extract_english_description(cve_obj: Dict[str, Any]) -> str:
    desc = ""
    container = cve_obj
    # NVD JSON 2.0 typically: cve['descriptions'] list
    descriptions = container.get("descriptions")
    if isinstance(descriptions, list):
        for d in descriptions:
            if not isinstance(d, dict):
                continue
            if d.get("lang") == "en" and isinstance(d.get("value"), str):
                desc = d["value"]
                break
    # Older-ish shapes sometimes: cve['description']['description_data']
    if not desc:
        d2 = container.get("description")
        if isinstance(d2, dict):
            dd = d2.get("description_data")
            if isinstance(dd, list):
                for d in dd:
                    if isinstance(d, dict) and d.get("lang") == "en" and isinstance(d.get("value"), str):
                        desc = d["value"]
                        break
    return desc or ""


def _extract_cwe(cve_obj: Dict[str, Any]) -> Optional[str]:
    weaknesses = cve_obj.get("weaknesses")
    if isinstance(weaknesses, list):
        for w in weaknesses:
            if not isinstance(w, dict):
                continue
            d = w.get("description")
            if isinstance(d, list):
                for item in d:
                    if isinstance(item, dict) and item.get("lang") == "en":
                        val = item.get("value")
                        if isinstance(val, str) and val.startswith("CWE-"):
                            return val
    # Legacy
    pt = cve_obj.get("problemtype")
    if isinstance(pt, dict):
        pd = pt.get("problemtype_data")
        if isinstance(pd, list):
            for p in pd:
                if not isinstance(p, dict):
                    continue
                desc = p.get("description")
                if isinstance(desc, list):
                    for item in desc:
                        if isinstance(item, dict) and item.get("value", "").startswith("CWE-"):
                            return item.get("value")
    return None


def _extract_cvss_v3(metrics_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # NVD 2.0: metrics might have cvssMetricV31/cvssMetricV30
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics_obj.get(key)
        if isinstance(arr, list) and arr:
            m = arr[0]
            if isinstance(m, dict):
                cvss = m.get("cvssData")
                if isinstance(cvss, dict):
                    # Return small subset.
                    out = {
                        "version": cvss.get("version"),
                        "vectorString": cvss.get("vectorString"),
                        "baseScore": cvss.get("baseScore"),
                        "baseSeverity": cvss.get("baseSeverity"),
                    }
                    return {k: v for k, v in out.items() if v is not None}
    return None


def _extract_references(cve_obj: Dict[str, Any], limit: int = 10) -> List[str]:
    urls: List[str] = []
    refs = cve_obj.get("references")
    if isinstance(refs, list):
        for r in refs:
            if not isinstance(r, dict):
                continue
            url = r.get("url")
            if isinstance(url, str) and url:
                urls.append(url)
            if len(urls) >= limit:
                break
    # Legacy
    if not urls:
        ref = cve_obj.get("references")
        if isinstance(ref, dict):
            rd = ref.get("reference_data")
            if isinstance(rd, list):
                for r in rd:
                    if isinstance(r, dict) and isinstance(r.get("url"), str):
                        urls.append(r["url"])
                    if len(urls) >= limit:
                        break
    return urls


def _iter_cpe_matches(configurations: Any) -> Iterator[Dict[str, Any]]:
    """Yield cpeMatch dicts from various NVD configuration shapes."""

    if not configurations:
        return

    # NVD 2.0 shape: configurations: list of {nodes:[...]} (or dict with nodes)
    if isinstance(configurations, dict):
        nodes = configurations.get("nodes")
        if isinstance(nodes, list):
            for node in nodes:
                yield from _iter_cpe_matches(node)
        # Some shapes: configurations contains "configurations" nested
        nested = configurations.get("configurations")
        if nested is not None:
            yield from _iter_cpe_matches(nested)
        return

    if isinstance(configurations, list):
        for item in configurations:
            yield from _iter_cpe_matches(item)
        return

    if not isinstance(configurations, dict):
        return


def _iter_nodes(obj: Any) -> Iterator[Dict[str, Any]]:
    if isinstance(obj, dict):
        # Yield dict itself so nodes with direct cpeMatch aren't missed.
        yield obj
        if "nodes" in obj and isinstance(obj["nodes"], list):
            for n in obj["nodes"]:
                if isinstance(n, dict):
                    yield n
                    yield from _iter_nodes(n)
        if "children" in obj and isinstance(obj["children"], list):
            for n in obj["children"]:
                if isinstance(n, dict):
                    yield n
                    yield from _iter_nodes(n)
    elif isinstance(obj, list):
        for x in obj:
            yield from _iter_nodes(x)


def _extract_cpe_evidence(configurations: Any) -> List[CpeMatchEvidence]:
    matches: List[CpeMatchEvidence] = []

    # NVD 2.0: configurations is list of nodes. Each node can have cpeMatch list.
    for node in _iter_nodes(configurations):
        cm = node.get("cpeMatch")
        if isinstance(cm, list):
            for c in cm:
                if not isinstance(c, dict):
                    continue
                criteria = str(c.get("criteria") or c.get("cpe23Uri") or "")
                parsed = _parse_cpe_23_full(criteria)
                vendor = parsed["vendor"]
                product = parsed["product"]
                version = parsed["version"]
                matches.append(
                    CpeMatchEvidence(
                        criteria=criteria,
                        cpe_part=parsed["part"],
                        cpe_vendor=vendor,
                        cpe_product=product,
                        cpe_version=version,
                        cpe_target_sw=parsed["target_sw"],
                        version_start_including=c.get("versionStartIncluding"),
                        version_start_excluding=c.get("versionStartExcluding"),
                        version_end_including=c.get("versionEndIncluding"),
                        version_end_excluding=c.get("versionEndExcluding"),
                    )
                )

    return matches


def _iter_nvd_cves(nvd_path: str, limit: Optional[int] = None) -> Iterator[CveRecord]:
    """Iterate CVEs from a local NVD dataset file.

    Supports common shapes:
    - NVD JSON 2.0: {"vulnerabilities": [{"cve": {...}} , ...]}
    - Older: {"CVE_Items": [...]} (best-effort)
    """

    def _detect_nvd_mode(path: str) -> Optional[str]:
        # Cheap shape sniff: avoid reading entire file.
        try:
            with open(path, "rb") as f:
                head = f.read(262144)
        except Exception:
            return None

        stripped = head.lstrip()
        if stripped.startswith(b"["):
            return "list"

        head_text = head.decode("utf-8", errors="ignore")
        if '"vulnerabilities"' in head_text:
            return "vulnerabilities"
        if '"CVE_Items"' in head_text:
            return "CVE_Items"
        return None

    def _iter_items_streaming(path: str, prefix: str) -> Iterator[Any]:
        import ijson  # local import so json-only environments still work

        with open(path, "rb") as f:
            try:
                yield from ijson.items(f, prefix, use_float=True)
            except TypeError:
                # Older ijson versions may not support use_float.
                yield from ijson.items(f, prefix)

    # Prefer streaming parse for huge datasets to avoid OOM.
    mode = None
    try:
        import ijson  # type: ignore  # noqa: F401

        mode = _detect_nvd_mode(nvd_path)
    except Exception:
        mode = None

    items_iter: Iterable[Any]
    if mode in {"vulnerabilities", "CVE_Items", "list"}:
        prefix = {
            "vulnerabilities": "vulnerabilities.item",
            "CVE_Items": "CVE_Items.item",
            "list": "item",
        }[mode]
        items_iter = _iter_items_streaming(nvd_path, prefix)
    else:
        # Fallback: full load (may require lots of RAM).
        data = _read_json(nvd_path)

        # Determine item list.
        items: List[Any] = []
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            items = data["vulnerabilities"]
            mode = "vulnerabilities"
        elif isinstance(data, dict) and isinstance(data.get("CVE_Items"), list):
            items = data["CVE_Items"]
            mode = "CVE_Items"
        elif isinstance(data, list):
            items = data
            mode = "list"
        else:
            raise ValueError(f"Unrecognized NVD dataset shape: {nvd_path}")
        items_iter = items

    count = 0
    for item in items_iter:
        if limit is not None and count >= limit:
            break

        cve_obj: Optional[Dict[str, Any]] = None
        published: Optional[str] = None
        configurations: Any = None
        metrics: Dict[str, Any] = {}

        if mode == "vulnerabilities":
            if isinstance(item, dict):
                cve_obj = item.get("cve") if isinstance(item.get("cve"), dict) else None
                # Dataset shape: published/configurations/metrics are nested under the cve object.
                if isinstance(cve_obj, dict):
                    published_val = cve_obj.get("published")
                    published = published_val if isinstance(published_val, str) else None
                    configurations = cve_obj.get("configurations")
                    metrics = cve_obj.get("metrics") if isinstance(cve_obj.get("metrics"), dict) else {}
        elif mode == "CVE_Items":
            if isinstance(item, dict):
                cve = item.get("cve")
                cve_obj = cve if isinstance(cve, dict) else None
                pub = item.get("publishedDate") or item.get("published")
                published = pub if isinstance(pub, str) else None
                configurations = item.get("configurations")
                impact = item.get("impact")
                if isinstance(impact, dict):
                    metrics = impact
        else:
            cve_obj = item if isinstance(item, dict) else None

        if not cve_obj:
            continue

        # CVE id
        cve_id = ""
        meta = cve_obj.get("id")
        if isinstance(meta, str):
            cve_id = meta
        else:
            meta2 = cve_obj.get("CVE_data_meta")
            if isinstance(meta2, dict) and isinstance(meta2.get("ID"), str):
                cve_id = meta2["ID"]

        if not cve_id.startswith("CVE-"):
            continue

        description = _extract_english_description(cve_obj)
        cwe = _extract_cwe(cve_obj)
        cvss_v3 = _extract_cvss_v3(metrics) if isinstance(metrics, dict) else None
        references = _extract_references(cve_obj)

        cpe_matches = _extract_cpe_evidence(configurations)
        has_cpe_evidence = len(cpe_matches) > 0

        yield CveRecord(
            cve_id=cve_id,
            published=published,
            description=description,
            cwe=cwe,
            cvss_v3=cvss_v3,
            references=references,
            has_cpe_evidence=has_cpe_evidence,
            cpe_matches=cpe_matches,
        )

        count += 1


def _find_nvd_dataset() -> str:
    candidates = [
        "nvd_cves_all.json",
        os.path.join("data", "nvd_cves_all.json"),
        os.path.join("nvd", "nvd_cves_all.json"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
        # Also check within product/ for convenience.
        p2 = os.path.join("product", p)
        if os.path.exists(p2):
            return p2
    raise FileNotFoundError(
        "NVD dataset not found. Expected one of: "
        + ", ".join(candidates)
        + " (also checked under product/)."
    )


# ----------------------------
# Matching logic
# ----------------------------


@dataclass
class CandidateMatch:
    product_key: str
    cve: CveRecord

    match_source: str  # cpe | description | reference | description+cpe
    matched_cpe: Optional[str]

    # Vendor/product evidence flags
    vendor_in_evidence: bool
    product_phrase_hits: int

    # Version
    version_match: str  # yes | no | unknown

    match_confidence: str  # high | medium


def _build_evidence_text(cve: CveRecord) -> str:
    parts = [cve.description or ""] + (cve.references or [])
    return _norm_space(" ".join(parts))


def _reference_contains_any(urls: List[str], tokens: Set[str]) -> bool:
    """Check if any reference URL contains any token as a substring.

    For URLs, substring matching is acceptable and deterministic.
    """
    toks = {t for t in tokens if t}
    if not toks or not urls:
        return False
    for u in urls:
        ul = (u or "").lower()
        if any(t in ul for t in toks):
            return True
    return False


def _evidence_contains_vendor(evidence: str, vendor_tokens: Set[str]) -> bool:
    # Simple token containment.
    words = set(_tokenize_words(evidence))
    return any(t in words for t in vendor_tokens)


def _count_phrase_hits(evidence: str, strong_phrases: List[str]) -> int:
    """Count phrase hits using word-boundary matching.

    Prevents substring false positives (e.g., matching "edge" inside "knowledge").
    """
    hits = 0
    for phrase in strong_phrases:
        phrase = phrase.strip().lower()
        if not phrase:
            continue

        tokens = _tokenize_words(phrase)
        if not tokens:
            continue

        if len(tokens) == 1:
            rx = re.compile(rf"\\b{re.escape(tokens[0])}\\b")
        else:
            rx = re.compile(r"\\b" + r"[\\s\-_]+".join(re.escape(t) for t in tokens) + r"\\b")

        if rx.search(evidence):
            hits += 1

    return hits


def _collect_global_cpe_product_vendors(cve: CveRecord, product_to_vendors: Dict[str, Set[str]]) -> None:
    for cm in cve.cpe_matches:
        if cm.cpe_vendor and cm.cpe_product:
            product_to_vendors.setdefault(cm.cpe_product, set()).add(cm.cpe_vendor)


def _candidate_pairs_for_product(rec: Dict[str, Any]) -> Set[Tuple[str, str]]:
    vendor = str(rec.get("vendor_normalized") or "unknown").strip().lower()
    out: Set[Tuple[str, str]] = set()
    mc = rec.get("mapping_candidates")
    if isinstance(mc, list):
        for item in mc:
            if isinstance(item, dict):
                v = str(item.get("vendor") or vendor).strip().lower()
                p = str(item.get("product") or "").strip().lower()
                if v and p:
                    out.add((v, p))
    # Always include (vendor, product_normalized) as a candidate.
    pn = str(rec.get("product_normalized") or "").strip().lower()
    if vendor and pn:
        out.add((vendor, pn))
    return out


def _candidate_products_for_product(rec: Dict[str, Any]) -> Set[str]:
    """Return candidate product tokens (no vendor) used for CPE evidence matching."""
    out: Set[str] = set()
    pn = str(rec.get("product_normalized") or "").strip().lower()
    pf = str(rec.get("product_family") or "").strip().lower()
    if pn:
        out.add(pn)
        # Also include the short core (strip leading vendor_ if present).
        # This helps match CPE products like "visual_studio_code" vs "microsoft_visual_studio_code".
        if "_" in pn:
            out.add(pn.split("_", 1)[-1])
    if pf:
        out.add(pf)

    mc = rec.get("mapping_candidates")
    if isinstance(mc, list):
        for item in mc:
            if isinstance(item, dict):
                p = str(item.get("product") or "").strip().lower()
                if p:
                    out.add(p)

    return out


def _version_in_bounds(
    installed: Tuple[int, ...],
    start_incl: Optional[str],
    start_excl: Optional[str],
    end_incl: Optional[str],
    end_excl: Optional[str],
) -> Optional[bool]:
    """Return True/False if bounds present; None if no usable bounds."""

    has_any = any([start_incl, start_excl, end_incl, end_excl])
    if not has_any:
        return None

    if start_incl:
        sv = _parse_version_tuple(str(start_incl))
        if sv is not None and _compare_versions(installed, sv) < 0:
            return False

    if start_excl:
        sv = _parse_version_tuple(str(start_excl))
        if sv is not None and _compare_versions(installed, sv) <= 0:
            return False

    if end_incl:
        ev = _parse_version_tuple(str(end_incl))
        if ev is not None and _compare_versions(installed, ev) > 0:
            return False

    if end_excl:
        ev = _parse_version_tuple(str(end_excl))
        if ev is not None and _compare_versions(installed, ev) >= 0:
            return False

    return True


_TEXT_VERSION_PATTERNS = [
    # before 148, prior to 1.2.3
    re.compile(r"\b(before|prior to)\s+(?P<v>\d+(?:\.\d+){0,5})\b"),
    # < 126
    re.compile(r"\b<\s*(?P<v>\d+(?:\.\d+){0,5})\b"),
    # through 147 / up to 147
    re.compile(r"\b(through|up to)\s+(?P<v>\d+(?:\.\d+){0,5})\b"),
    # versions 145-147
    re.compile(r"\bversions?\s+(?P<a>\d+(?:\.\d+){0,5})\s*[-–]\s*(?P<b>\d+(?:\.\d+){0,5})\b"),
]


def _conservative_text_version_check(evidence: str, installed_v: Tuple[int, ...]) -> Optional[bool]:
    """Best-effort conservative version rejection using text.

    Returns:
      - False if we can confidently say installed version is outside the described vulnerable range
      - True if installed version is plausibly within range
      - None if no usable version clues
    """

    for rx in _TEXT_VERSION_PATTERNS:
        m = rx.search(evidence)
        if not m:
            continue

        if "v" in m.groupdict():
            bound = _parse_version_tuple(m.group("v"))
            if bound is None:
                continue

            if rx.pattern.startswith("\\b(before") or "prior to" in rx.pattern or rx.pattern.startswith("\\b<"):
                # vulnerable if installed < bound
                return _compare_versions(installed_v, bound) < 0

            if "through" in rx.pattern or "up to" in rx.pattern:
                # vulnerable if installed <= bound
                return _compare_versions(installed_v, bound) <= 0

        if "a" in m.groupdict() and "b" in m.groupdict():
            a = _parse_version_tuple(m.group("a"))
            b = _parse_version_tuple(m.group("b"))
            if a is None or b is None:
                continue
            if _compare_versions(installed_v, a) < 0:
                return False
            if _compare_versions(installed_v, b) > 0:
                return False
            return True

    return None


def _published_year(published: Optional[str]) -> Optional[int]:
    if not published or not isinstance(published, str):
        return None
    m = re.match(r"^(\d{4})", published)
    return int(m.group(1)) if m else None


def _best_candidate_for_cve(cands: List[CandidateMatch]) -> Optional[CandidateMatch]:
    """Pick a single best product assignment for a CVE to reduce collisions.

    Preference order:
    - cpe-sourced over text
    - more phrase hits
    - vendor presence
    """

    if not cands:
        return None

    def score(c: CandidateMatch) -> Tuple[int, int, int]:
        src = 2 if c.match_source == "cpe" else 1
        v = 1 if c.vendor_in_evidence else 0
        return (src, c.product_phrase_hits, v)

    return max(cands, key=score)


def map_inventory_to_cves(
    inventory: List[Dict[str, Any]],
    nvd_path: str,
    limit_cves: Optional[int] = None,
    endpoint_platform_override: Optional[str] = None,
    min_cve_year: Optional[int] = None,
    max_cve_year: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Main mapping routine.

    Returns:
      (output_records, summary_counts)
    """

    profiles: Dict[str, ProductProfile] = {}
    skip_info: Dict[str, Tuple[bool, Optional[str]]] = {}
    installed_pairs: Dict[str, Set[Tuple[str, str]]] = {}
    installed_products: Dict[str, Set[str]] = {}

    for rec in inventory:
        key = str(rec.get("product_normalized") or "unknown")
        # Keep key unique per vendor+product to avoid accidental merges.
        key = f"{rec.get('vendor_normalized','unknown')}|{key}".lower()
        profiles[key] = _build_product_profile(rec)
        skip_info[key] = _should_skip_product(profiles[key])
        installed_pairs[key] = _candidate_pairs_for_product(rec)
        installed_products[key] = _candidate_products_for_product(rec)

    endpoint_platform = _infer_endpoint_platform(inventory)
    if endpoint_platform_override:
        endpoint_platform = endpoint_platform_override

    # Global CPE product->vendors map used to detect globally-unique products.
    product_to_vendors: Dict[str, Set[str]] = {}

    # Stage-1 candidate matches collected per CVE id for collision filtering.
    candidates_by_cve: Dict[str, List[CandidateMatch]] = {}

    # Precompile product phrase list per product for text matching.
    # To avoid O(products * CVEs) heavy scanning, we still need phrase checks;
    # inventories are small, so a straightforward check remains acceptable.

    for cve in _iter_nvd_cves(nvd_path, limit=limit_cves):
        if min_cve_year is not None or max_cve_year is not None:
            y = _published_year(cve.published)
            if y is None:
                continue
            if min_cve_year is not None and y < int(min_cve_year):
                continue
            if max_cve_year is not None and y > int(max_cve_year):
                continue

        _collect_global_cpe_product_vendors(cve, product_to_vendors)

        evidence = _build_evidence_text(cve)

        # If structured CPE evidence exists, we ONLY use CPE criteria to generate candidates.
        if cve.has_cpe_evidence:
            for cm in cve.cpe_matches:
                if not cm.cpe_vendor or not cm.cpe_product:
                    continue

                # Platform guard: reject mobile-only CPEs when endpoint is clearly desktop (and vice versa).
                if not _platform_allows_cpe_target_sw(endpoint_platform, cm.cpe_target_sw):
                    continue

                cpe_pair = (cm.cpe_vendor, cm.cpe_product)

                for pkey, pairs in installed_pairs.items():
                    if skip_info[pkey][0]:
                        continue

                    profile = profiles[pkey]

                    # Primary: exact (vendor, product) candidate.
                    # Secondary: match by product token alone when vendor normalization differs,
                    # but still require product identity alignment.
                    product_only_ok = cm.cpe_product in installed_products.get(pkey, set())
                    exact_pair_ok = cpe_pair in pairs

                    if not exact_pair_ok and not product_only_ok:
                        continue

                    # Vendor consistency is about whether the evidence vendor aligns with the
                    # installed vendor identity. This supports cases like:
                    # publisher: "Python Software Foundation" -> vendor_normalized: python_software_foundation
                    # CPE vendor: "python"
                    vendor_hit = cm.cpe_vendor in profile.vendor_tokens or cm.cpe_vendor == profile.vendor_normalized
                    phrase_hits = 1  # at least one structured hit

                    # Version decision via bounds/criteria.
                    installed_vt = _parse_version_tuple(profile.version_normalized)
                    version_match = "unknown"
                    if installed_vt is not None:
                        in_bounds = _version_in_bounds(
                            installed_vt,
                            cm.version_start_including,
                            cm.version_start_excluding,
                            cm.version_end_including,
                            cm.version_end_excluding,
                        )
                        if in_bounds is False:
                            version_match = "no"
                        elif in_bounds is True:
                            version_match = "yes"
                        else:
                            # If CPE criteria has a concrete version, require equality.
                            if cm.cpe_version and cm.cpe_version not in {"*", "-"}:
                                cv = _parse_version_tuple(cm.cpe_version)
                                if cv is not None:
                                    version_match = "yes" if _compare_versions(installed_vt, cv) == 0 else "no"

                    # How strongly does the description mention this product?
                    # Used later to filter "secondary platform" CPE listings (e.g., Flash CVEs listing Edge).
                    desc_hits = 0
                    if cve.description:
                        desc_hits = _count_phrase_hits(_norm_space(cve.description), profile.strong_phrases)

                    cand = CandidateMatch(
                        product_key=pkey,
                        cve=cve,
                        match_source="cpe",
                        matched_cpe=cm.criteria,
                        vendor_in_evidence=vendor_hit,
                        product_phrase_hits=desc_hits,
                        version_match=version_match,
                        match_confidence="high",
                    )
                    candidates_by_cve.setdefault(cve.cve_id, []).append(cand)

        else:
            # Text-only fallback.
            for pkey, profile in profiles.items():
                if skip_info[pkey][0]:
                    continue

                phrase_hits = _count_phrase_hits(evidence, profile.strong_phrases)
                if phrase_hits <= 0:
                    continue

                vendor_hit = _evidence_contains_vendor(evidence, profile.vendor_tokens)

                # Conservative candidate generation: require vendor hit OR strong uniqueness will be
                # considered later in validation. Here we keep it as a candidate if phrase hits >= 1.
                cand = CandidateMatch(
                    product_key=pkey,
                    cve=cve,
                    match_source="description" if (cve.description and any(ph in _norm_space(cve.description) for ph in profile.strong_phrases)) else "reference",
                    matched_cpe=None,
                    vendor_in_evidence=vendor_hit,
                    product_phrase_hits=phrase_hits,
                    version_match="unknown",
                    match_confidence="medium",
                )
                candidates_by_cve.setdefault(cve.cve_id, []).append(cand)

    # Determine globally unique products from CPE ecosystem (data-driven, deterministic).
    globally_unique_products: Set[str] = set()
    for prod, vendors in product_to_vendors.items():
        if len(vendors) == 1 and prod:
            globally_unique_products.add(prod)

    # Stage-2 validation + collision filtering.
    matched_by_product: Dict[str, List[CandidateMatch]] = {k: [] for k in profiles.keys()}

    for cve_id, cands in candidates_by_cve.items():
        # Prefer structured evidence: if any CPE-sourced candidate exists, discard text candidates.
        any_cpe = any(c.match_source == "cpe" for c in cands)
        working = [c for c in cands if c.match_source == "cpe"] if any_cpe else list(cands)

        # Drop obvious version mismatches for CPE candidates.
        working = [c for c in working if not (c.match_source == "cpe" and c.version_match == "no")]
        if not working:
            continue

        # For text-only CVEs, resolve collisions aggressively:
        # - if exactly one best-scoring product exists -> keep it
        # - if tie -> drop all (minimize false positives)
        if not any_cpe and len(working) > 1:
            def score(c: CandidateMatch) -> Tuple[int, int]:
                return (c.product_phrase_hits, 1 if c.vendor_in_evidence else 0)

            best_score = max(score(c) for c in working)
            best_group = [c for c in working if score(c) == best_score]
            if len(best_group) != 1:
                continue
            working = best_group

        # Validate each remaining candidate.
        for cand in working:
            profile = profiles[cand.product_key]
            skip, _ = skip_info[cand.product_key]
            if skip:
                continue

            evidence = _build_evidence_text(cand.cve)

            # Extra precision guard for CPE-sourced matches:
            # If the CVE description doesn't mention the installed product at all, and references
            # don't contain vendor/product hints, treat it as a likely "secondary affected platform"
            # listing (high false-positive risk for endpoint inventory).
            if cand.match_source == "cpe":
                if cand.product_phrase_hits <= 0:
                    ref_tokens = set(profile.vendor_tokens)
                    ref_tokens.add(profile.product_family)
                    if not _reference_contains_any(cand.cve.references, ref_tokens):
                        continue

            # Vendor consistency.
            if cand.match_source != "cpe":
                if not cand.vendor_in_evidence:
                    allow = False
                    for mc in profile.mapping_candidates:
                        if not isinstance(mc, dict):
                            continue
                        prod = str(mc.get("product") or "").strip().lower()
                        if prod and prod in globally_unique_products and re.search(rf"\\b{re.escape(prod)}\\b", evidence):
                            allow = True
                            break
                    if not allow:
                        continue
            else:
                if not cand.vendor_in_evidence:
                    cpe_prod = None
                    if cand.matched_cpe:
                        _, cpe_prod, _ = _parse_cpe_23(cand.matched_cpe)
                    if not cpe_prod or cpe_prod not in globally_unique_products:
                        continue

            # Collision rejection for text-only candidates.
            if cand.match_source != "cpe":
                for other_key, other_profile in profiles.items():
                    if other_key == cand.product_key:
                        continue
                    other_hits = _count_phrase_hits(evidence, other_profile.strong_phrases)
                    if other_hits > cand.product_phrase_hits:
                        cand = None
                        break
                if cand is None:
                    continue

            # Version relevance.
            installed_vt = _parse_version_tuple(profile.version_normalized)
            if installed_vt is None:
                cand.version_match = "unknown"
            else:
                tv = _conservative_text_version_check(evidence, installed_vt)
                if tv is False:
                    continue
                if tv is True:
                    cand.version_match = "yes"

                # If still unknown, apply a temporal relevance filter for software
                # when the CVE is old and provides no usable version bounds.
                if cand.version_match == "unknown":
                    major = installed_vt[0] if installed_vt else 0
                    year = _published_year(cand.cve.published)
                    if year is not None:
                        current_year = _dt.datetime.now(_dt.timezone.utc).year
                        cve_age = current_year - year

                        # Fast-release software (browsers, etc.) where major versions
                        # climb rapidly. Old CVEs almost never apply to current versions
                        # when no version bounds confirm applicability.
                        if major >= 100 and cve_age >= 3:
                            continue
                        if major >= 50 and cve_age >= 4:
                            continue
                        if major >= 20 and cve_age >= 6:
                            continue

                        # General cutoff: any CVE older than 8 years with no version
                        # evidence is extremely unlikely to be relevant.
                        if cve_age >= 8:
                            continue

            # Hard age cap: regardless of version_match, CVEs with
            # version_match != "yes" older than 10 years are almost
            # certainly not applicable to current software.  Even
            # version_match="yes" CVEs are capped at 15 years because
            # very old CPE version fields (e.g. "xp", "v.x") can
            # produce false positive version matches.
            year = _published_year(cand.cve.published)
            if year is not None:
                cve_age = _dt.datetime.now(_dt.timezone.utc).year - year
                if cand.version_match != "yes":
                    if cve_age >= 10:
                        continue
                else:
                    if cve_age >= 15:
                        continue

            matched_by_product[profile_key(cand.product_key)].append(cand)

    # Build output records.
    output: List[Dict[str, Any]] = []
    total_skipped = 0
    total_matched_products = 0
    total_cve_matches = 0

    for pkey, profile in profiles.items():
        skipped, reason = skip_info[pkey]
        if skipped:
            total_skipped += 1

        matches = matched_by_product.get(pkey, []) if not skipped else []

        if matches:
            total_matched_products += 1

        matched_cves: List[Dict[str, Any]] = []
        for m in sorted({x.cve.cve_id: x for x in matches}.values(), key=lambda x: x.cve.cve_id):
            total_cve_matches += 1
            matched_cves.append(
                {
                    "cve_id": m.cve.cve_id,
                    "published": m.cve.published,
                    "description": (m.cve.description or "")[:6000],
                    "cwe": m.cve.cwe,
                    "match_source": m.match_source,
                    "version_match": m.version_match,
                    "match_confidence": m.match_confidence,
                    "cvss_v3": m.cve.cvss_v3,
                    "references": m.cve.references,
                    "matched_cpe": m.matched_cpe,
                }
            )

        output.append(
            {
                "display_product": profile.display_product,
                "vendor_normalized": profile.vendor_normalized,
                "product_normalized": profile.product_normalized,
                "version_normalized": profile.version_normalized,
                "skipped": bool(skipped),
                "skip_reason": reason,
                "matched_cve_count": len(matched_cves),
                "matched_cves": matched_cves,
            }
        )

    summary = {
        "total_products_processed": len(profiles),
        "total_products_skipped": total_skipped,
        "total_products_matched_with_cves": total_matched_products,
        "total_cve_matches_found": total_cve_matches,
    }

    return output, summary


def profile_key(pkey: str) -> str:
    # Normalization helper (kept separate for future extension).
    return pkey


def _print_summary(output: List[Dict[str, Any]], summary: Dict[str, int]) -> None:
    print("CVE match summary")
    print("-" * 30)
    print(f"total products processed: {summary['total_products_processed']}")
    print(f"total products skipped: {summary['total_products_skipped']}")
    print(f"total products matched with CVEs: {summary['total_products_matched_with_cves']}")
    print(f"total CVE matches found: {summary['total_cve_matches_found']}")
    print("")

    for rec in output:
        if rec.get("skipped"):
            continue
        cnt = int(rec.get("matched_cve_count") or 0)
        if cnt <= 0:
            continue
        dp = rec.get("display_product")
        ver = rec.get("version_normalized")
        print(f"{dp} | {ver} | {cnt}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic CVE matching for one endpoint inventory")
    parser.add_argument(
        "--inventory",
        default=os.path.join("product", "output", "product_inventory.json"),
        help="Path to normalized inventory JSON (default: product/output/product_inventory.json)",
    )
    parser.add_argument(
        "--nvd",
        default=None,
        help="Optional path to NVD dataset JSON (otherwise auto-detected)",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("product", "output", "product_cve_matches.json"),
        help="Output path (default: product/output/product_cve_matches.json)",
    )
    parser.add_argument(
        "--endpoint-platform",
        default=None,
        choices=["windows", "macos", "linux", "unknown"],
        help=(
            "Override inferred endpoint platform for CPE target_sw filtering. "
            "If omitted, platform is inferred from install_location paths."
        ),
    )
    parser.add_argument(
        "--limit-cves",
        type=int,
        default=None,
        help="Optional limit for debugging (process only first N CVEs)",
    )
    parser.add_argument(
        "--min-cve-year",
        type=int,
        default=None,
        help="Optional minimum CVE published year to consider (inclusive).",
    )
    parser.add_argument(
        "--max-cve-year",
        type=int,
        default=None,
        help="Optional maximum CVE published year to consider (inclusive).",
    )

    args = parser.parse_args(argv)

    inventory_path = args.inventory
    if not os.path.exists(inventory_path):
        raise FileNotFoundError(
            f"Inventory file not found: {inventory_path}. "
            "Run build_product_inventory.py first to generate product/output/product_inventory.json"
        )

    nvd_path = args.nvd or _find_nvd_dataset()
    if not os.path.exists(nvd_path):
        raise FileNotFoundError(f"NVD dataset not found at: {nvd_path}")

    inventory = _load_inventory(inventory_path)
    output, summary = map_inventory_to_cves(
        inventory,
        nvd_path,
        limit_cves=args.limit_cves,
        endpoint_platform_override=args.endpoint_platform,
        min_cve_year=args.min_cve_year,
        max_cve_year=args.max_cve_year,
    )

    _write_json(args.output, output)
    _print_summary(output, summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
