"""Build a clean product identity layer from a single endpoint's installed applications.

This script intentionally does NOT perform any CVE/CPE lookup, ML scoring, or external enrichment.
It focuses only on:
- extracting installed applications from one endpoint record
- normalizing vendor/product/version
- deduplicating / merging obvious subcomponents (e.g., Python feature components)
- producing high-quality product fingerprints and mapping candidates for later steps

Design rule:
- Do NOT do vendor-only matching. Vendor is part of the key, but product identity must remain distinct
  (e.g., Microsoft Edge vs Microsoft Visual Studio Code).

Input (choose one):
- A single endpoint record JSON containing an `applications` array.
- OR a Firestore document in the `endpoint data` collection (read-only) loaded using a
    Firebase/Google Cloud service account key.

Output:
- product/output/product_inventory.json

Usage:
    python product/build_product_inventory.py --input product/input/endpoint_sample.json

    # Firestore (read-only)
    python product/build_product_inventory.py \
        --firestore-service-account product/secrets/serviceAccountKey.json \
        --firestore-collection "endpoint data" \
        --firestore-doc-id <DOC_ID>

"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){1,8})(?:\b|[^\d])")


def _slugify(value: str) -> str:
    """Make a stable identifier token: lowercase, ascii-ish, underscores."""
    v = value.strip().lower()
    v = v.replace("&", " and ")
    v = re.sub(r"\(.*?\)", " ", v)  # drop parenthetical noise
    v = re.sub(r"[^a-z0-9]+", "_", v)
    v = re.sub(r"_+", "_", v).strip("_")
    return v


def normalize_vendor(raw_publisher: Optional[str]) -> str:
    """Normalize publisher into a stable vendor identifier.

    We use deterministic rules + a small synonym table because publisher strings vary a lot.
    """

    if not raw_publisher:
        return "unknown"

    pub = raw_publisher.strip()
    pub_l = pub.lower().strip()

    # Common exact/near-exact synonyms.
    vendor_map = {
        "microsoft": "microsoft",
        "microsoft corporation": "microsoft",
        "microsoft corp.": "microsoft",
        "mozilla": "mozilla",
        "mozilla corporation": "mozilla",
        "python software foundation": "python_software_foundation",
        "eset": "eset",
        "eset, spol. s r.o.": "eset",
        "oracle": "oracle",
        "oracle and/or its affiliates": "oracle",
        "portswigger": "portswigger",
        "portswigger web security": "portswigger",
        "google llc": "google",
        "google": "google",
        "google inc.": "google",
        "google inc": "google",
        "jetbrains s.r.o.": "jetbrains",
        "jetbrains": "jetbrains",
        "nvidia corporation": "nvidia",
        "nvidia": "nvidia",
        "brave software inc": "brave_software",
        "brave software": "brave_software",
        "openjs foundation": "nodejs_foundation",
        "node.js foundation": "nodejs_foundation",
        "kakao corp.": "kakao",
        "kakao": "kakao",
        "don ho": "don_ho",
        "igor pavlov": "igor_pavlov",
        "intel corporation": "intel",
        "intel": "intel",
    }

    # Normalize punctuation/spacing before lookup.
    pub_norm_key = re.sub(r"\s+", " ", re.sub(r"[\u00a0\t]", " ", pub_l)).strip()
    if pub_norm_key in vendor_map:
        return vendor_map[pub_norm_key]

    # Heuristic cleanup: drop corporate suffixes, then slugify.
    pub_clean = pub_norm_key
    pub_clean = re.sub(r",?\s*(inc\.|inc|ltd\.|ltd|llc|gmbh|corp\.|corp|co\.|co|company|corporation|s\.r\.o\.?)\b", "", pub_clean)
    pub_clean = re.sub(r"\s+", " ", pub_clean).strip(" ,")

    slug = _slugify(pub_clean)
    return slug if slug else "unknown"


@dataclass(frozen=True)
class NormalizedApp:
    raw_name: str
    raw_publisher: Optional[str]
    raw_version: Optional[str]
    install_location: Optional[str]
    install_date: Optional[str]

    vendor_normalized: str
    product_normalized: str
    display_product: str
    version_normalized: Optional[str]
    product_family: str
    mapping_candidates: List[Dict[str, str]]


def _extract_version_from_text(text: str) -> Optional[str]:
    m = _VERSION_RE.search(text)
    if not m:
        return None
    return m.group(1)


def normalize_version(raw_version: Optional[str], raw_name: str) -> Optional[str]:
    """Normalize version string.

    - Keeps dotted numeric versions.
    - If raw_version is missing/unknown, tries to extract from the application name.
    """
    if raw_version:
        v = raw_version.strip()
        if not v or v.lower() in {"unknown", "n/a", "na", "none"}:
            v = ""
        if v:
            # Accept versions like 145.0.3800.82, 2023.10.2.3
            m = re.match(r"^(\d+(?:\.\d+){0,8})(?:[\s\-\+].*)?$", v)
            if m:
                return m.group(1)
            # If the field contains extra text, attempt extraction.
            extracted = _extract_version_from_text(v)
            if extracted:
                return extracted

    # Fallback: extract from name.
    extracted = _extract_version_from_text(raw_name)
    return extracted


def _strip_noise_tokens(name: str) -> str:
    """Remove common non-identity tokens from application names.

    This is intentionally conservative: it should not collapse distinct products.
    """
    s = name
    # Language/arch tags.
    s = re.sub(r"\b\(x64[^)]*\)", " ", s, flags=re.IGNORECASE)
    s = re.sub(r"\b\(x86[^)]*\)", " ", s, flags=re.IGNORECASE)
    s = re.sub(r"\b\(arm64[^)]*\)", " ", s, flags=re.IGNORECASE)
    s = re.sub(r"\b(en\-us|en\-gb|fr\-fr|de\-de|es\-es)\b", " ", s, flags=re.IGNORECASE)

    # Installer context markers that are not product identity.
    s = re.sub(r"\b\(user\)\b", " ", s, flags=re.IGNORECASE)
    s = re.sub(r"\b\(system\)\b", " ", s, flags=re.IGNORECASE)

    s = re.sub(r"\s+", " ", s).strip()
    return s


def normalize_product(vendor_normalized: str, raw_name: str, raw_version: Optional[str]) -> Tuple[str, str, str]:
    """Return (product_normalized, product_family, display_product).

    Product normalization is rule-based and must keep distinct products separate.
    We avoid vendor-only matching by deriving an explicit product core from name patterns.
    """

    name = raw_name.strip()
    name_clean = _strip_noise_tokens(name)
    name_l = name_clean.lower()

    # Explicit patterns (more reliable than generic slugification).
    # Order matters: more specific patterns MUST come before generic ones.
    patterns: List[Tuple[re.Pattern[str], str, str, str]] = [
        # Mozilla
        (re.compile(r"^mozilla firefox\b", re.IGNORECASE), "mozilla_firefox", "firefox", "Mozilla Firefox"),
        # Google
        (re.compile(r"^google chrome\b", re.IGNORECASE), "chrome", "chrome", "Google Chrome"),
        # Microsoft — specific before general
        (re.compile(r"^microsoft edge webview2 runtime\b", re.IGNORECASE), "microsoft_edge_webview2_runtime", "edge_webview2", "Microsoft Edge WebView2 Runtime"),
        (re.compile(r"^microsoft edge\b", re.IGNORECASE), "microsoft_edge", "edge", "Microsoft Edge"),
        (re.compile(r"^microsoft teams\b", re.IGNORECASE), "microsoft_teams", "teams", "Microsoft Teams"),
        (re.compile(r"^microsoft onedrive\b", re.IGNORECASE), "microsoft_onedrive", "onedrive", "Microsoft OneDrive"),
        (re.compile(r"^microsoft visual studio code\b", re.IGNORECASE), "microsoft_visual_studio_code", "vscode", "Microsoft Visual Studio Code"),
        (re.compile(r"^microsoft visual c\+\+", re.IGNORECASE), "visual_c++", "visual_c++", "Microsoft Visual C++"),
        (re.compile(r"^microsoft \.net\b", re.IGNORECASE), ".net", ".net", "Microsoft .NET"),
        (re.compile(r"^(?:microsoft 365|office 16 click-to-run)\b", re.IGNORECASE), "365", "365", "Microsoft 365"),
        (re.compile(r"^windows subsystem for linux\b", re.IGNORECASE), "windows_subsystem_for_linux", "wsl", "Windows Subsystem for Linux"),
        # Brave
        (re.compile(r"^brave\b", re.IGNORECASE), "brave", "brave", "Brave"),
        # Node.js
        (re.compile(r"^node\.?js\b", re.IGNORECASE), "node.js", "node.js", "Node.js"),
        # 7-Zip
        (re.compile(r"^7-?zip\b", re.IGNORECASE), "7-zip", "7-zip", "7-Zip"),
        # Notepad++
        (re.compile(r"^notepad\+\+", re.IGNORECASE), "notepad++", "notepad++", "Notepad++"),
        # JetBrains
        (re.compile(r"^pycharm\b", re.IGNORECASE), "pycharm", "pycharm", "PyCharm"),
        (re.compile(r"^intellij\b", re.IGNORECASE), "intellij_idea", "intellij_idea", "IntelliJ IDEA"),
        (re.compile(r"^webstorm\b", re.IGNORECASE), "webstorm", "webstorm", "WebStorm"),
        # PotPlayer
        (re.compile(r"^potplayer\b", re.IGNORECASE), "potplayer", "potplayer", "PotPlayer"),
        # NVIDIA
        (re.compile(r"^cuda toolkit\b", re.IGNORECASE), "cuda_toolkit", "cuda_toolkit", "CUDA Toolkit"),
        # PortSwigger
        (re.compile(r"^burp suite\b.*community edition", re.IGNORECASE), "burp_suite_community_edition", "burp_suite", "Burp Suite Community Edition"),
        (re.compile(r"^burp suite\b", re.IGNORECASE), "burp_suite", "burp_suite", "Burp Suite"),
        # ESET
        (re.compile(r"^eset endpoint security\b", re.IGNORECASE), "eset_endpoint_security", "eset_endpoint_security", "ESET Endpoint Security"),
        (re.compile(r"^eset management agent\b", re.IGNORECASE), "eset_management_agent", "eset_management_agent", "ESET Management Agent"),
        # Oracle
        (re.compile(r"^oracle virtualbox guest additions\b", re.IGNORECASE), "oracle_virtualbox_guest_additions", "virtualbox", "Oracle VirtualBox Guest Additions"),
    ]

    for rx, product_norm, family, display in patterns:
        if rx.search(name_clean):
            return product_norm, family, display

    # Python (mergeable subcomponents) — normalize *product* to "python".
    # Rationale: the Windows Python installer registers many "features" separately
    # (Core Interpreter, Standard Library, Documentation, Launcher, etc.) but for
    # vulnerability mapping we want a single product identity: python.
    has_python = bool(re.search(r"\bpython\b", name_l))
    name_has_version = bool(re.search(r"\b\d+(?:\.\d+){1,4}\b", name_l))
    version_field_has_version = bool(raw_version and re.match(r"^\d+(?:\.\d+){1,8}", raw_version.strip()))
    if has_python and (name_has_version or version_field_has_version or name_l.startswith("python ") or name_l == "python"):
        return "python", "python", "Python"

    # Generic fallback: derive a product core from the cleaned name.
    # Strip trailing version numbers to avoid embedding version in product identity.
    # E.g. "7-Zip 25.01" -> "7-Zip", "PyCharm 2025.2.3" -> "PyCharm"
    name_for_product = re.sub(
        r"[\s\-]+(?:version[\s\-]+)?v?\d+(?:\.\d+){1,8}(?:[\s\-].*)?$",
        "", name_clean, flags=re.IGNORECASE,
    ).strip() or name_clean
    core = _slugify(name_for_product)
    if not core:
        core = "unknown_product"

    # Avoid duplicating vendor when the app name already starts with it.
    if core.startswith(vendor_normalized + "_"):
        product_norm = core
    else:
        product_norm = f"{vendor_normalized}_{core}" if vendor_normalized != "unknown" else core

    # Family heuristic: last token cluster (kept conservative).
    # If product_norm has vendor prefix, family becomes the remainder.
    family = product_norm
    if vendor_normalized != "unknown" and product_norm.startswith(vendor_normalized + "_"):
        family = product_norm[len(vendor_normalized) + 1 :]

    # Display: title-case cleaned name.
    display = name_clean

    return product_norm, family, display


def build_mapping_candidates(vendor_normalized: str, product_normalized: str, product_family: str) -> List[Dict[str, str]]:
    """Generate candidate identifiers for later CVE/CPE mapping.

    We intentionally create multiple candidates:
    - family-level keyword (e.g., vscode)
    - full normalized identifier (e.g., microsoft_visual_studio_code)
    - short product core (e.g., visual_studio_code)

    These are NOT matched here; they are just emitted as deterministic candidates.
    """

    def add(cands: List[Dict[str, str]], product: str) -> None:
        if not product:
            return
        item = {"vendor": vendor_normalized, "product": product}
        if item not in cands:
            cands.append(item)

    cands: List[Dict[str, str]] = []

    # Full.
    add(cands, product_normalized)

    # Family.
    add(cands, product_family)

    # Short core (strip vendor prefix when present).
    short_core = product_normalized
    prefix = vendor_normalized + "_"
    if vendor_normalized != "unknown" and product_normalized.startswith(prefix):
        short_core = product_normalized[len(prefix) :]
    add(cands, short_core)

    # Explicit aliases for a few known cases (deterministic).
    aliases = {
        "microsoft_visual_studio_code": ["vscode"],
        "mozilla_firefox": ["firefox"],
        "microsoft_edge": ["edge"],
        "burp_suite_community_edition": ["burp_suite"],
    }
    for alias in aliases.get(product_normalized, []):
        add(cands, alias)

    # CPE aliases: map our product_normalized to known NVD CPE (vendor, product) pairs.
    # This enables matching even when the publisher name differs from the NVD vendor.
    _cpe_aliases: Dict[str, List[Tuple[str, str]]] = {
        "chrome": [("google", "chrome")],
        "mozilla_firefox": [("mozilla", "firefox")],
        "microsoft_edge": [("microsoft", "edge_chromium"), ("microsoft", "edge")],
        "microsoft_visual_studio_code": [("microsoft", "visual_studio_code")],
        "python": [("python", "python"), ("python_software_foundation", "python")],
        "node.js": [("nodejs", "node.js"), ("nodejs", "nodejs")],
        "7-zip": [("7-zip", "7-zip"), ("igor_pavlov", "7-zip")],
        "notepad++": [("notepad\\+\\+", "notepad\\+\\+"), ("don_ho", "notepad\\+\\+"), ("notepad-plus-plus", "notepad\\+\\+")],
        "brave": [("brave", "brave"), ("brave", "brave_browser")],
        "pycharm": [("jetbrains", "pycharm")],
        "intellij_idea": [("jetbrains", "intellij_idea")],
        "webstorm": [("jetbrains", "webstorm")],
        "potplayer": [("kakao", "potplayer")],
        "cuda_toolkit": [("nvidia", "cuda_toolkit")],
        "365": [("microsoft", "365_apps_for_enterprise"), ("microsoft", "office")],
        ".net": [("microsoft", ".net_framework"), ("microsoft", ".net")],
        "visual_c++": [("microsoft", "visual_c\\+\\+")],
        "virtualbox": [("oracle", "vm_virtualbox"), ("oracle", "virtualbox")],
        "oracle_virtualbox_guest_additions": [("oracle", "vm_virtualbox"), ("oracle", "virtualbox")],
        "microsoft_onedrive": [("microsoft", "onedrive")],
        "microsoft_teams": [("microsoft", "teams")],
        "eset_endpoint_security": [("eset", "endpoint_security")],
        "windows_subsystem_for_linux": [("microsoft", "windows_subsystem_for_linux")],
        "burp_suite_community_edition": [("portswigger", "burp_suite")],
        "burp_suite": [("portswigger", "burp_suite")],
    }
    for nvd_vendor, nvd_product in _cpe_aliases.get(product_normalized, []):
        item = {"vendor": nvd_vendor, "product": nvd_product}
        if item not in cands:
            cands.append(item)

    return cands


def normalize_application(app: Dict[str, Any]) -> NormalizedApp:
    raw_name = str(app.get("name") or "").strip()
    raw_publisher = app.get("publisher")
    raw_version = app.get("version")
    install_location = app.get("install_location")
    install_date = app.get("install_date")

    vendor_norm = normalize_vendor(raw_publisher)
    product_norm, family, display = normalize_product(vendor_norm, raw_name, str(raw_version) if raw_version is not None else None)
    version_norm = normalize_version(raw_version, raw_name)
    candidates = build_mapping_candidates(vendor_norm, product_norm, family)

    return NormalizedApp(
        raw_name=raw_name,
        raw_publisher=raw_publisher,
        raw_version=raw_version,
        install_location=install_location,
        install_date=install_date,
        vendor_normalized=vendor_norm,
        product_normalized=product_norm,
        display_product=display,
        version_normalized=version_norm,
        product_family=family,
        mapping_candidates=candidates,
    )


def _parse_version_tuple(v: Optional[str]) -> Tuple[int, ...]:
    if not v:
        return tuple()
    parts = [p for p in v.split(".") if p.isdigit()]
    if not parts:
        return tuple()
    return tuple(int(p) for p in parts)


def merge_normalized_apps(apps: Sequence[NormalizedApp]) -> List[Dict[str, Any]]:
    """Merge deduplicated products.

    Key rule: only merge when *product identity* is the same (vendor + product_normalized),
    plus a special-case merge bucket for Python subcomponents.
    """

    buckets: Dict[Tuple[str, str], List[NormalizedApp]] = {}
    for a in apps:
        key = (a.vendor_normalized, a.product_normalized)

        # Merge all python subcomponents into one product identity.
        if a.product_normalized == "python":
            key = (a.vendor_normalized, "python")

        buckets.setdefault(key, []).append(a)

    merged: List[Dict[str, Any]] = []
    for (vendor_norm, product_norm), items in sorted(buckets.items(), key=lambda kv: kv[0]):
        # Pick a representative record deterministically.
        # - Prefer the one with a version.
        # - If multiple versions, take the highest numeric tuple.
        best = max(
            items,
            key=lambda x: (_parse_version_tuple(x.version_normalized), 1 if x.install_location else 0, len(x.raw_name)),
        )

        # Union mapping candidates.
        cand: List[Dict[str, str]] = []
        for it in items:
            for c in it.mapping_candidates:
                if c not in cand:
                    cand.append(c)

        merged_record: Dict[str, Any] = {
            "raw_name": best.raw_name,
            "raw_publisher": best.raw_publisher,
            "raw_version": best.raw_version,
            "install_location": best.install_location,
            "install_date": best.install_date,
            "vendor_normalized": vendor_norm,
            "product_normalized": product_norm,
            "display_product": best.display_product,
            "version_normalized": best.version_normalized,
            "product_family": best.product_family,
            "mapping_candidates": cand,
            "merged_from": sorted({it.raw_name for it in items}),
        }
        merged.append(merged_record)

    return merged


def _find_applications_array(endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Locate the applications array within a likely Firestore endpoint record."""

    for key in ("applications", "apps", "installed_applications"):
        v = endpoint.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]

    # Common wrappers.
    data = endpoint.get("data")
    if isinstance(data, dict):
        for key in ("applications", "apps"):
            v = data.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]

    raise ValueError("Could not find an applications array in endpoint record")


def _write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _load_endpoint_record_from_firestore(
    service_account_path: str,
    collection: str,
    doc_id: Optional[str],
    project_id: Optional[str],
) -> Tuple[Dict[str, Any], str]:
    """Load exactly one endpoint record from Firestore.

    This is READ-ONLY. No writes are performed.
    Returns: (endpoint_record_dict, firestore_doc_id)
    """

    try:
        from google.cloud import firestore  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Missing dependency google-cloud-firestore. Install with: pip install google-cloud-firestore"
        ) from e

    if not os.path.exists(service_account_path):
        raise FileNotFoundError(
            f"Service account key not found at: {service_account_path}. "
            "Place it at product/secrets/serviceAccountKey.json (and keep it out of git)."
        )

    # Prefer explicit credentials from file to avoid relying on ADC env vars.
    if project_id:
        client = firestore.Client.from_service_account_json(service_account_path, project=project_id)
    else:
        client = firestore.Client.from_service_account_json(service_account_path)

    col_ref = client.collection(collection)

    if doc_id:
        snap = col_ref.document(doc_id).get()
        if not snap.exists:
            raise ValueError(f"Firestore document not found: collection={collection!r} doc_id={doc_id!r}")
        data = snap.to_dict() or {}
        if not isinstance(data, dict):
            raise ValueError("Firestore document did not deserialize to an object")
        return data, snap.id

    # If doc_id is omitted, load the first document deterministically by query limit.
    # Note: without an explicit order_by, Firestore doesn't guarantee ordering, but limit(1)
    # is still useful as a quick smoke test.
    docs = list(col_ref.limit(1).stream())
    if not docs:
        raise ValueError(f"No documents found in Firestore collection: {collection!r}")
    snap = docs[0]
    data = snap.to_dict() or {}
    if not isinstance(data, dict):
        raise ValueError("Firestore document did not deserialize to an object")
    return data, snap.id


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build normalized product inventory from one endpoint record")

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", help="Path to endpoint JSON containing applications array")
    source.add_argument(
        "--firestore-service-account",
        help=(
            "Path to Firebase/Google service account key JSON. "
            "Recommended: product/secrets/serviceAccountKey.json"
        ),
    )
    parser.add_argument(
        "--firestore-collection",
        default="endpoint data",
        help='Firestore collection name (default: "endpoint data")',
    )
    parser.add_argument(
        "--firestore-doc-id",
        default=None,
        help="Firestore document id to fetch (if omitted, fetches 1 document via limit(1))",
    )
    parser.add_argument(
        "--firestore-project-id",
        default=None,
        help="Optional GCP project id override (usually embedded in the service account)",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("product", "output", "product_inventory.json"),
        help="Output JSON path (default: product/output/product_inventory.json)",
    )

    args = parser.parse_args(argv)

    endpoint: Dict[str, Any]
    firestore_doc_id: Optional[str] = None
    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            endpoint = json.load(f)
        if not isinstance(endpoint, dict):
            raise ValueError("Input JSON must be an object (endpoint record)")
    else:
        endpoint, firestore_doc_id = _load_endpoint_record_from_firestore(
            service_account_path=args.firestore_service_account,
            collection=args.firestore_collection,
            doc_id=args.firestore_doc_id,
            project_id=args.firestore_project_id,
        )

    raw_apps = _find_applications_array(endpoint)
    normalized = [normalize_application(a) for a in raw_apps if str(a.get("name") or "").strip()]
    merged = merge_normalized_apps(normalized)

    _write_json(args.output, merged)

    # Print summary.
    print("Product inventory summary")
    print("-" * 30)
    if firestore_doc_id:
        print(f"firestore_doc_id: {firestore_doc_id}")
    print(f"total raw applications: {len(raw_apps)}")
    print(f"total normalized products: {len(merged)}")
    print("")
    for rec in merged:
        v = rec["vendor_normalized"]
        p = rec["product_normalized"]
        ver = rec.get("version_normalized")
        print(f"{v} | {p} | {ver}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
