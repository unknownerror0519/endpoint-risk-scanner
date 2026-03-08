from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path
from typing import Any, Iterable, Optional


BASE_DIR = Path(__file__).resolve().parent
NVD_DIR = BASE_DIR / "nvd"
KEV_PATH = BASE_DIR / "kev" / "kev_catalog.json"
ROOT_KEV_PATH = BASE_DIR / "known_exploited_vulnerabilities.json"
NVD_ALL_PATH = BASE_DIR / "nvd_cves_all.json"
OUTPUT_CSV = BASE_DIR / "data" / "training_dataset.csv"


COLUMNS = [
    "cve_id",
    "published",
    "cvss_score",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality",
    "integrity",
    "availability",
    "cwe",
    "description",
    "label",
]


def _open_maybe_gzip(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8")
    return path.open(mode="r", encoding="utf-8")


def _first_english_value(items: list[dict[str, Any]], value_key: str = "value") -> str:
    for item in items:
        if item.get("lang") == "en" and isinstance(item.get(value_key), str):
            return item[value_key]
    for item in items:
        if isinstance(item.get(value_key), str):
            return item[value_key]
    return ""


def _extract_cwe(weaknesses: list[dict[str, Any]]) -> str:
    candidates: list[str] = []
    for weakness in weaknesses:
        desc = weakness.get("description")
        if isinstance(desc, list):
            value = _first_english_value(desc)
            if value:
                candidates.append(value)

    for value in candidates:
        if value.startswith("CWE-"):
            return value

    return candidates[0] if candidates else ""


def _pick_metric(metric_list: Any) -> Optional[dict[str, Any]]:
    if not isinstance(metric_list, list) or not metric_list:
        return None
    for metric in metric_list:
        if isinstance(metric, dict) and metric.get("type") == "Primary":
            return metric
    for metric in metric_list:
        if isinstance(metric, dict):
            return metric
    return None


def _extract_cvss_from_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    # Prefer v3.1, then v3.0, then v2.
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric = _pick_metric(metrics.get(key))
        if metric and isinstance(metric.get("cvssData"), dict):
            cvss = metric["cvssData"]
            return {
                "cvss_score": cvss.get("baseScore"),
                "attack_vector": cvss.get("attackVector", ""),
                "attack_complexity": cvss.get("attackComplexity", ""),
                "privileges_required": cvss.get("privilegesRequired", ""),
                "user_interaction": cvss.get("userInteraction", ""),
                "confidentiality": cvss.get("confidentialityImpact", ""),
                "integrity": cvss.get("integrityImpact", ""),
                "availability": cvss.get("availabilityImpact", ""),
            }

    metric = _pick_metric(metrics.get("cvssMetricV2"))
    if metric and isinstance(metric.get("cvssData"), dict):
        cvss = metric["cvssData"]
        return {
            "cvss_score": cvss.get("baseScore"),
            "attack_vector": cvss.get("accessVector", ""),
            "attack_complexity": cvss.get("accessComplexity", ""),
            "privileges_required": cvss.get("authentication", ""),
            "user_interaction": "",
            "confidentiality": cvss.get("confidentialityImpact", ""),
            "integrity": cvss.get("integrityImpact", ""),
            "availability": cvss.get("availabilityImpact", ""),
        }

    return {
        "cvss_score": None,
        "attack_vector": "",
        "attack_complexity": "",
        "privileges_required": "",
        "user_interaction": "",
        "confidentiality": "",
        "integrity": "",
        "availability": "",
    }


def _as_float_or_none(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def load_kev_cve_ids(kev_path: Path) -> set[str]:
    with kev_path.open("r", encoding="utf-8") as f:
        kev = json.load(f)

    vulns = kev.get("vulnerabilities")
    if not isinstance(vulns, list):
        return set()

    ids: set[str] = set()
    for v in vulns:
        if isinstance(v, dict):
            cve_id = v.get("cveID") or v.get("cveId") or v.get("cve")
            if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
                ids.add(cve_id)
    return ids


def iter_nvd_files(nvd_dir: Path) -> list[Path]:
    files = sorted(list(nvd_dir.glob("*.json")) + list(nvd_dir.glob("*.json.gz")))
    return [p for p in files if p.is_file()]


def _iter_top_level_array_items_from_file(path: Path, array_key: str) -> Iterable[Any]:
    """Stream-iterate items of a top-level JSON array value for a given key.

    This avoids loading the entire file into memory and uses only the built-in json module.
    Assumptions (true for NVD JSON feeds):
    - The file is a JSON object with a top-level key named `array_key` whose value is an array.
    """

    decoder = json.JSONDecoder()
    buffer = ""
    read_size = 1024 * 1024  # 1 MiB

    with path.open("r", encoding="utf-8") as f:
        # 1) Find the start of the array for the given key.
        needle = f'"{array_key}"'
        while True:
            idx = buffer.find(needle)
            if idx != -1:
                buffer = buffer[idx + len(needle) :]
                break
            chunk = f.read(read_size)
            if not chunk:
                raise ValueError(f"Key {array_key!r} not found in JSON: {path}")
            buffer += chunk

        # Move to ':' then '['
        while True:
            colon = buffer.find(":")
            if colon != -1:
                buffer = buffer[colon + 1 :]
                break
            chunk = f.read(read_size)
            if not chunk:
                raise ValueError(f"Malformed JSON after key {array_key!r}: {path}")
            buffer += chunk

        while True:
            bracket = buffer.find("[")
            if bracket != -1:
                buffer = buffer[bracket + 1 :]
                break
            chunk = f.read(read_size)
            if not chunk:
                raise ValueError(f"Array for key {array_key!r} not found: {path}")
            buffer += chunk

        # 2) Decode items one by one.
        pos = 0
        while True:
            # Ensure we have enough data
            if pos >= len(buffer) - 1:
                chunk = f.read(read_size)
                if chunk:
                    buffer = buffer[pos:] + chunk
                    pos = 0
                else:
                    buffer = buffer[pos:]
                    pos = 0

            # Skip whitespace and commas
            while True:
                while pos < len(buffer) and buffer[pos].isspace():
                    pos += 1
                if pos < len(buffer) and buffer[pos] == ",":
                    pos += 1
                    continue
                break

            if pos >= len(buffer):
                chunk = f.read(read_size)
                if not chunk:
                    raise ValueError(f"Unexpected EOF while reading array {array_key!r}: {path}")
                buffer += chunk
                continue

            # End of array
            if buffer[pos] == "]":
                return

            # Decode next JSON value
            try:
                obj, end = decoder.raw_decode(buffer, pos)
            except json.JSONDecodeError:
                chunk = f.read(read_size)
                if not chunk:
                    raise
                buffer += chunk
                continue

            pos = end
            yield obj


def _iter_vulnerabilities_from_sources(nvd_files: list[Path]) -> Iterable[dict[str, Any]]:
    if nvd_files:
        for path in nvd_files:
            with _open_maybe_gzip(path) as f:
                data = json.load(f)
            vulnerabilities = data.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            for item in vulnerabilities:
                if isinstance(item, dict):
                    yield item
        return

    # Fallback: stream parse the "vulnerabilities" array from the large combined file.
    if not NVD_ALL_PATH.exists():
        raise FileNotFoundError(
            f"No NVD JSON files found in: {NVD_DIR} and fallback not found: {NVD_ALL_PATH}"
        )

    for item in _iter_top_level_array_items_from_file(NVD_ALL_PATH, "vulnerabilities"):
        if isinstance(item, dict):
            yield item


def _extract_row_from_vuln_item(item: dict[str, Any], kev_ids: set[str]) -> Optional[dict[str, Any]]:
    cve = item.get("cve")
    if not isinstance(cve, dict):
        return None

    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        return None

    published = cve.get("published")
    if not isinstance(published, str):
        published = ""

    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}

    cvss = _extract_cvss_from_metrics(metrics)
    cvss_score = _as_float_or_none(cvss.get("cvss_score"))
    if cvss_score is None:
        return None

    weaknesses = cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        weaknesses = []

    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        descriptions = []

    return {
        "cve_id": cve_id,
        "published": published,
        "cvss_score": cvss_score,
        "attack_vector": cvss.get("attack_vector", ""),
        "attack_complexity": cvss.get("attack_complexity", ""),
        "privileges_required": cvss.get("privileges_required", ""),
        "user_interaction": cvss.get("user_interaction", ""),
        "confidentiality": cvss.get("confidentiality", ""),
        "integrity": cvss.get("integrity", ""),
        "availability": cvss.get("availability", ""),
        "cwe": _extract_cwe(weaknesses),
        "description": _first_english_value(descriptions),
        "label": 1 if cve_id in kev_ids else 0,
    }


def build_training_dataset() -> None:
    # Canonicalize KEV location: always read KEV_PATH.
    if not KEV_PATH.exists() and ROOT_KEV_PATH.exists():
        KEV_PATH.parent.mkdir(parents=True, exist_ok=True)
        ROOT_KEV_PATH.replace(KEV_PATH)

    if not KEV_PATH.exists():
        raise FileNotFoundError(
            f"KEV catalog not found at {KEV_PATH} (expected {ROOT_KEV_PATH} to be moved here)"
        )

    nvd_files = iter_nvd_files(NVD_DIR)
    kev_ids = load_kev_cve_ids(KEV_PATH)

    seen_cve_ids: set[str] = set()
    total_written = 0
    positives = 0
    negatives = 0

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=COLUMNS)
        writer.writeheader()

        for vuln_item in _iter_vulnerabilities_from_sources(nvd_files):
            row = _extract_row_from_vuln_item(vuln_item, kev_ids)
            if row is None:
                continue

            cve_id = row["cve_id"]
            if cve_id in seen_cve_ids:
                continue
            seen_cve_ids.add(cve_id)

            writer.writerow(row)
            total_written += 1
            if row["label"] == 1:
                positives += 1
            else:
                negatives += 1

    print(f"total_rows_written={total_written}")
    print(f"positives={positives}")
    print(f"negatives={negatives}")


if __name__ == "__main__":
    build_training_dataset()
