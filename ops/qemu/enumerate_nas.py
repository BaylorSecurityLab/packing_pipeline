#!/usr/bin/env python3
"""Enumerate EVERY packer family+version in benign_packed, gathering candidate
.exe samples across ALL of a family+version's testcases (the Type is invariant
across testcases, so the >=2 distinct payloads a consensus label needs may be
drawn from any testcase(s)).  Emits worklist.json with a per-family sample pool.

Also cross-references manifest/*.yaml to recover the configuration_id/family/
version when available; synthesizes them from the dir name otherwise.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RT = REPO / "empirical_results/qemu_runtime"


def session():
    import smbclient
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("PACKER_NAS_"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
    smbclient.register_session(
        "10.100.99.29",
        username=os.environ["PACKER_NAS_USERNAME"],
        password=os.environ["PACKER_NAS_PASSWORD"],
    )
    return smbclient


def split_family_version(nas_dir: str):
    """astral_pe_1.6.0.0 -> (astral_pe, 1.6.0.0); upx_v3.95_3.95 -> (upx, 3.95)."""
    m = re.match(r"^(.*?)_v?[\d].*?_([\d][\w.]*)$", nas_dir)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"^(.*?)_([\d][\w.]*)$", nas_dir)
    if m:
        return m.group(1), m.group(2)
    return nas_dir, "?"


def main() -> int:
    smb = session()
    base = "//10.100.99.29/samples/benign_packed"
    families = sorted(e.name for e in smb.scandir(base) if e.is_dir())
    work = []
    for nas_dir in families:
        fam, ver = split_family_version(nas_dir)
        pool = []          # (size, testcase_rel, name) where testcase_rel is ""
                           # for exes directly under the family dir
        rep_tc = None
        try:
            entries = list(smb.scandir(f"{base}/{nas_dir}"))
        except Exception as ex:
            print(f"[warn] {nas_dir}: scandir failed {ex}")
            continue
        # (a) exes directly under the family+version dir
        for e in entries:
            if not e.is_dir() and e.name.lower().endswith(".exe"):
                try:
                    sz = smb.stat(f"{base}/{nas_dir}/{e.name}").st_size
                except Exception:
                    sz = 1 << 40
                pool.append((sz, "", e.name))
        if pool:
            rep_tc = ""
        # (b) exes inside testcase subdirs (skip helper dirs like temp/)
        for tc in sorted(e.name for e in entries if e.is_dir()):
            try:
                for e in smb.scandir(f"{base}/{nas_dir}/{tc}"):
                    if e.name.lower().endswith(".exe"):
                        try:
                            sz = smb.stat(f"{base}/{nas_dir}/{tc}/{e.name}").st_size
                        except Exception:
                            sz = 1 << 40
                        pool.append((sz, tc, e.name))
            except Exception:
                pass
            if rep_tc is None and pool:
                rep_tc = tc
        if len(pool) < 2:
            print(f"[skip] {nas_dir}: only {len(pool)} exe(s) across testcases")
            continue
        pool.sort()                       # smallest first (fastest to trace)
        samples = [
            {"testcase": tc, "name": nm,
             "remote": (f"{base}/{nas_dir}/{tc}/{nm}" if tc
                        else f"{base}/{nas_dir}/{nm}")}
            for _, tc, nm in pool[:8]
        ]
        work.append({
            "nas_dir": nas_dir,
            "family": fam,
            "version": ver,
            "testcase": rep_tc or ".",
            "n": len(pool),
            "cid": None,                   # filled from manifest below if present
            "samples": samples,
        })

    # recover configuration_id from manifest yamls (best-effort)
    try:
        import yaml
        for mf in (REPO / "manifest").glob("*.yaml"):
            try:
                m = yaml.safe_load(mf.read_text()) or {}
            except Exception:
                continue
            for c in (m.get("conditions") or []):
                cid = c.get("configuration_id")
                fam = str(c.get("packer_family", "")).lower()
                verc = str(c.get("packer_version", ""))
                if not cid:
                    continue
                for w in work:
                    if w["cid"] is None and w["family"].lower().startswith(fam[:4]) \
                       and verc and verc in w["nas_dir"]:
                        w["cid"] = cid
    except Exception:
        pass

    (RT / "worklist.json").write_text(json.dumps(work, indent=2))
    fams = sorted({w["family"] for w in work})
    print(f"[enum] {len(work)} family+versions, {len(fams)} families")
    print("[enum] families:", ", ".join(fams))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
