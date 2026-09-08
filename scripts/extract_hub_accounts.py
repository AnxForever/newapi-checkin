#!/usr/bin/env python3
"""从 All API Hub 浏览器插件的 LevelDB 存储提取站点与账号，生成 newapi-checkin 配置。

用法：python3 scripts/extract_hub_accounts.py
只输出统计与脱敏信息；用 --write 才会落盘生成配置文件。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EXT_ID = "lapnciffpekdengooeolaienkeoilfeo"
EDGE_EXT_ID = "pcokpjaffghgipcgjhapgdpeddlhblaa"

# 数据源：Chrome 各 profile + Edge
SOURCES = [
    Path.home() / "AppData/Local/Google/Chrome/User Data" / p / "Local Extension Settings" / EXT_ID
    for p in ("Default", "Profile 1", "Profile 6", "Profile 8", "Profile 16")
] + [
    Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default/Local Extension Settings" / EDGE_EXT_ID
]


def extract_objects(data: str) -> list[dict]:
    # LevelDB value 是 JSON 字符串，内部 JSON 被转义一层：\" -> "
    unescaped = data.replace("\\\\", "\x00").replace('\\"', '"').replace("\x00", "\\")
    pattern = re.compile(r'"id":"account-[0-9a-f-]{36}"')
    objs: list[dict] = []
    seen: set[int] = set()
    for m in pattern.finditer(unescaped):
        start = m.start() - 1
        if start in seen:
            continue
        seen.add(start)
        try:
            obj = json.JSONDecoder().raw_decode(unescaped, start)[0]
        except Exception:
            continue
        if isinstance(obj, dict) and obj.get("site_url"):
            objs.append(obj)
    return objs


def site_id_from_url(url: str) -> str:
    host = url.split("//")[-1].split("/")[0]
    host = host.split(":")[0]
    return host.replace(".", "-")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="全量重写配置文件（覆盖注册表与账号文件，慎用）")
    ap.add_argument("--merge", action="store_true", help="增量导入：新站点追加、已有站点按 user_id upsert（保留开关/非 hub 站点/历史文件名）")
    args = ap.parse_args()

    objs = []
    for src in SOURCES:
        ldb = sorted(src.glob("*.log")) + sorted(src.glob("*.ldb"))
        if not ldb:
            print(f"[跳过] 无数据: {src}", file=sys.stderr)
            continue
        data = "".join(p.read_text(encoding="utf-8", errors="replace") for p in ldb)
        found = extract_objects(data)
        print(f"[读取] {src} -> {len(found)} 条记录")
        objs.extend(found)
    if not objs:
        print("所有数据源均无记录", file=sys.stderr)
        return 1

    # LevelDB 日志按写入顺序追加，快照历史重复出现 → 按 (site_url, account id) 去重，保留最后一次（最新）
    dedup: dict[tuple[str, str], dict] = {}
    for o in objs:
        ai = o.get("account_info") or {}
        key = (o["site_url"], str(ai.get("id")))
        dedup[key] = o

    sites: dict[str, list[dict]] = {}
    for o in dedup.values():
        sites.setdefault(o["site_url"], []).append(o)

    print(f"共 {len(sites)} 个站点 / {len(dedup)} 个账号（去重后）")
    for url, accs in sites.items():
        print(f"  {url} ({len(accs)})")
        for o in accs:
            ai = o.get("account_info") or {}
            tok = ai.get("access_token") or ""
            print(
                f"      {o.get('site_name')} | {ai.get('username')} | "
                f"id={ai.get('id')} | token={tok[:14]}..."
            )

    if not args.write and not args.merge:
        return 0

    # 统一整理为 {sid: {user_id: {name, token, label}}}；空 token 跳过
    # （hub 里存在「站点在但当前会话 token 为空」的条目，导入后也无法查询/签到）
    hub: dict[str, dict[str, dict]] = {}
    skipped_empty = 0
    for url, accs in sites.items():
        sid = site_id_from_url(url)
        bucket = hub.setdefault(sid, {})
        for o in accs:
            ai = o.get("account_info") or {}
            token = ai.get("access_token") or ""
            if not token:
                skipped_empty += 1
                continue
            base = ai.get("username") or "acc"
            # 同站点同名账号展示名加序号（与全量写入口径一致）
            dup = sum(1 for a in bucket.values() if a["name"] == base or a["name"].startswith(base + "-"))
            name = base if dup == 0 else f"{base}-{dup + 1}"
            bucket[str(ai.get("id"))] = {
                "name": name,
                "token": token,
                "label": o.get("site_name") or sid,
                "domain": url,
            }
    if skipped_empty:
        print(f"[跳过] {skipped_empty} 个空 token 账号（未登录/会话已失效）")

    if args.merge:
        return merge_import(hub, Path.cwd())

    root = Path.cwd()
    sites_json = []
    for sid, accs in hub.items():
        label = next(iter(accs.values()))["label"]
        site = {
            "id": sid,
            "label": label,
            "domain": next(iter(accs.values()))["domain"],
            "accounts_file": f"{sid}_accounts.json",
            "state_file": f"{sid}_checkin_state.json",
        }
        if sid != "gorouter-app":  # gorouter 沿用历史文件名，见仓库 NewapiSite 注释
            sites_json.append(site)
        accounts = [{"name": a["name"], "access_token": a["token"], "user_id": uid} for uid, a in accs.items()]
        if accounts:
            (root / f"{sid}_accounts.json").write_text(
                json.dumps(accounts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            print(f"  写入 {sid}_accounts.json ({len(accounts)} 账号)")

    (root / "newapi_sites.json").write_text(
        json.dumps(sites_json, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"  写入 newapi_sites.json ({len(sites_json)} 站点)")
    return 0


def merge_import(hub: dict[str, dict[str, dict]], root: Path) -> int:
    """增量导入：新站点追加注册表、已有站点按 user_id 合并账号（upsert，不删本地）。

    与 --write（全量重写，覆盖注册表与全部账号文件）不同，merge 保留：
    注册表里的 auto_checkin 等手工字段与顺序、非 hub 来源站点（claude/jianzhile 等）、
    gorouter 历史文件名映射、本地已有但 hub 侧已删的账号（可能在别的设备登录）。
    agentrouter.org 是登录式专用域，跳过。token 有变化视为重新登录，就地更新。
    """
    sites_path = root / "newapi_sites.json"
    sites = json.loads(sites_path.read_text(encoding="utf-8"))
    known = {s["id"]: s for s in sites}
    added_sites, changes = [], []

    for sid, accs in hub.items():
        if sid == "agentrouter-org":
            continue
        acc_path = root / (known[sid].get("accounts_file") if sid in known else f"{sid}_accounts.json")
        existing = json.loads(acc_path.read_text(encoding="utf-8")) if acc_path.exists() else []
        by_uid = {str(a["user_id"]): a for a in existing}
        for uid, a in accs.items():
            if uid in by_uid:
                if by_uid[uid]["access_token"] != a["token"]:
                    by_uid[uid]["access_token"] = a["token"]
                    changes.append(f"[token 更新] {sid}:{a['name']}")
                continue
            by_uid[uid] = {"name": a["name"], "access_token": a["token"], "user_id": uid}
            changes.append(f"[新增账号] {sid}:{a['name']}")
        merged = list(by_uid.values())
        if merged != existing:
            acc_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"  合并 {acc_path.name}: {len(existing)} -> {len(merged)} 账号")
        if sid not in known and merged:
            sites.append({
                "id": sid,
                "label": next(iter(accs.values()))["label"],
                "domain": next(iter(accs.values()))["domain"],
                "accounts_file": acc_path.name,
                "state_file": f"{sid}_checkin_state.json",
            })
            added_sites.append(sid)

    if added_sites:
        sites_path.write_text(json.dumps(sites, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"注册表新增 {len(added_sites)} 站点: {', '.join(added_sites)}")
    for c in changes:
        print(f"  {c}")
    if not added_sites and not changes:
        print("无变化")
    return 0



if __name__ == "__main__":
    sys.exit(main())
