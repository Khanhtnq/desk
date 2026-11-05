"""Config as data: desk policy, copy registers, kill list.

Loaded once at startup, hashed, exposed read-only at GET /v1. A change to any file is a review
matter; the boot event records every hash so config history is itself a record.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import AREAS, EFFORTS, GATES, TIERS, TOPICS, VERDICTS


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@dataclass
class Config:
    dir: Path
    desk: dict
    copy_public: dict
    copy_programme: dict
    kill_list: dict
    hashes: dict[str, str]

    # ---- vocabularies ---------------------------------------------------------------------

    @property
    def tiers(self) -> dict[str, dict]:
        return self.desk.get("tiers") or {}

    @property
    def tier_order(self) -> list[str]:
        """Highest first, as the file lists them; the code's tuple is the fallback."""
        order = [t for t in self.tiers if t in TIERS]
        return order or list(TIERS)

    def tier_rank(self, tier: str | None) -> int:
        """0 is the most severe; unknown and None sort last."""
        order = self.tier_order
        return order.index(tier) if tier in order else len(order)

    def tier_label(self, tier: str | None) -> str:
        if not tier:
            return "—"
        return str((self.tiers.get(tier) or {}).get("label") or tier)

    def ceiling_micro(self, tier: str | None) -> int:
        xe = (self.tiers.get(tier or "") or {}).get("ceiling_xe") or 0
        return int(xe) * 1_000_000

    @property
    def areas(self) -> dict[str, str]:
        return {k: str(v) for k, v in (self.desk.get("areas") or {}).items() if k in AREAS} or {
            a: a for a in AREAS
        }

    @property
    def topics(self) -> dict[str, str]:
        return {k: str(v) for k, v in (self.desk.get("topics") or {}).items() if k in TOPICS} or {
            a: a for a in TOPICS
        }

    def area_vocab(self, kind: str) -> dict[str, str]:
        """What `area` means on a ticket of this kind: engineering areas on the bounty, topics on support."""
        return self.topics if kind == "support" else self.areas

    @property
    def verdicts(self) -> dict[str, str]:
        return {k: str(v) for k, v in (self.desk.get("verdicts") or {}).items() if k in VERDICTS} or {
            v: v for v in VERDICTS
        }

    @property
    def gates(self) -> dict[str, str]:
        return {k: str(v) for k, v in (self.desk.get("gates") or {}).items() if k in GATES} or {
            g: g for g in GATES
        }

    @property
    def effort_bands(self) -> dict[str, dict]:
        return {k: v for k, v in (self.desk.get("effort_bands") or {}).items() if k in EFFORTS}

    def effort_agent(self, effort_eng: str | None) -> str:
        return str((self.effort_bands.get(effort_eng or "") or {}).get("agent") or "—")

    def effort_label(self, effort_eng: str | None) -> str:
        return str((self.effort_bands.get(effort_eng or "") or {}).get("engineer") or (effort_eng or "—"))

    def effort_hours(self, effort_eng: str | None) -> tuple[float, float]:
        b = self.effort_bands.get(effort_eng or "") or {}
        return float(b.get("engineer_hours") or 0), float(b.get("agent_hours") or 0)

    # ---- awards ---------------------------------------------------------------------------

    @property
    def award_steps(self) -> dict[str, dict]:
        """Where an award lands under the ceiling, highest step first, as the file lists them."""
        return {k: dict(v) for k, v in (self.desk.get("award_steps") or {}).items() if isinstance(v, dict)}

    def award_grain(self, tier: str | None) -> int:
        return int((self.desk.get("award_grain") or {}).get(tier or "") or 1)

    def award_area_factor(self, area: str | None) -> float:
        return float((self.desk.get("award_area_factor") or {}).get(area or "") or 1)

    def award_xe(self, tier: str | None, step: str, area: str | None = None) -> int:
        """The whole-XE amount one step of a tier's ceiling comes to, rounded down to the tier's grain."""
        share = float((self.award_steps.get(step) or {}).get("share") or 0)
        raw = (self.ceiling_micro(tier) // 1_000_000) * share * self.award_area_factor(area)
        grain = self.award_grain(tier)
        return int(raw // grain) * grain

    # ---- github ---------------------------------------------------------------------------

    @property
    def repos(self) -> list[str]:
        return [str(r) for r in ((self.desk.get("github") or {}).get("repos") or [])]

    @property
    def primary_repo(self) -> str:
        return self.repos[0] if self.repos else "xeprotocol/xe"

    @property
    def label_map(self) -> dict:
        return (self.desk.get("github") or {}).get("labels") or {}

    def label_for(self, status: str, closed_reason: str | None) -> dict | None:
        m = self.label_map
        if status == "closed":
            return (m.get("closed") or {}).get(closed_reason or "")
        return m.get(status)

    def all_labels(self) -> list[dict]:
        out: list[dict] = []
        for k, v in self.label_map.items():
            if k == "closed":
                out.extend(v.values())
            else:
                out.append(v)
        return out

    @property
    def tool_label_names(self) -> set[str]:
        return {str(label["name"]) for label in self.all_labels()}

    # ---- internal tracker -----------------------------------------------------------------

    @property
    def internal_repo(self) -> str:
        """The engineering tracker (owner/repo); empty disables the read-only sync."""
        return str((self.desk.get("internal") or {}).get("repo") or "")

    @property
    def internal_aliases(self) -> dict[str, str]:
        """Short names an internal ticket uses for the public repos: `xe#8` → xeprotocol/xe #8."""
        raw = (self.desk.get("internal") or {}).get("aliases") or {}
        return {str(k).lower(): str(v) for k, v in raw.items()}

    # ---- copy -----------------------------------------------------------------------------

    @property
    def reply_templates(self) -> dict[str, str]:
        return {k: str(v) for k, v in (self.copy_public.get("reply_templates") or {}).items()}

    @property
    def triage_agent(self) -> dict:
        return self.desk.get("triage_agent") or {"model_id": "triage", "label": "triage import"}

    @property
    def programme(self) -> dict:
        return self.desk.get("programme") or {}


def load_config(config_dir: Path) -> Config:
    d = Path(config_dir)
    files = {
        "desk.yaml": d / "desk.yaml",
        "copy/public.yaml": d / "copy" / "public.yaml",
        "copy/programme.yaml": d / "copy" / "programme.yaml",
        "copy/kill_list.yaml": d / "copy" / "kill_list.yaml",
    }
    missing = [k for k, p in files.items() if not p.exists()]
    if missing:
        raise FileNotFoundError(f"config files missing in {d}: {missing}")
    return Config(
        dir=d,
        desk=_load_yaml(files["desk.yaml"]),
        copy_public=_load_yaml(files["copy/public.yaml"]),
        copy_programme=_load_yaml(files["copy/programme.yaml"]),
        kill_list=_load_yaml(files["copy/kill_list.yaml"]),
        hashes={k: _sha256_file(p) for k, p in files.items()},
    )


# ---- copy lint -------------------------------------------------------------------------------


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _flatten_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _flatten_strings(v)]
    return []


def lint_public_copy(cfg: Config, extra_texts: list[str] | None = None) -> list[str]:
    """Return a list of violations (empty means clean). Covers the public register, which includes the
    reply templates and bot messages, plus any extra texts the caller passes (templates, llms.txt)."""
    phrases = [p.lower() for p in cfg.kill_list.get("phrases", [])]
    words = [w.lower() for w in cfg.kill_list.get("words", [])]
    texts = _flatten_strings(cfg.copy_public) + list(extra_texts or [])
    violations: list[str] = []
    for t in texts:
        low = t.lower()
        for p in phrases:
            if p in low:
                violations.append(f"phrase {p!r} in: {t[:80]!r}")
        for w in words:
            if re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", low):
                violations.append(f"word {w!r} in: {t[:80]!r}")
    return violations


def strip_template(text: str) -> str:
    """Jinja and HTML roughly removed, for linting the prose of a template."""
    text = re.sub(r"{[{%#].*?[}%#]}", " ", text, flags=re.S)
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.S)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S)
    return re.sub(r"<[^>]+>", " ", text)
