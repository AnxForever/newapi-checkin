"""hub 插件增量导入（merge_import）的离线单测。

不发任何上游请求、不碰真实浏览器数据 —— 用临时目录里的假注册表/账号文件驱动。
    python -m pytest tests/test_hub_import.py -q
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from extract_hub_accounts import merge_import, site_id_from_url  # noqa: E402


@pytest.fixture
def sandbox(tmp_path):
	"""预置注册表：一个 hub 站点（含历史文件名映射 + auto_checkin=False）、一个非 hub 站点。"""
	(sandbox := tmp_path)  # noqa: F841
	(tmp_path / "newapi_sites.json").write_text(json.dumps([
		{"id": "demo-com", "label": "Demo", "domain": "https://demo.com",
		 "auto_checkin": False, "accounts_file": "demo_accounts.json", "state_file": "demo_state.json"},
		{"id": "claude-x", "label": "非hub站", "domain": "https://claude.x"},
	], ensure_ascii=False), encoding="utf-8")
	(tmp_path / "demo_accounts.json").write_text(json.dumps([
		{"name": "老账号", "access_token": "old", "user_id": "1"},
		{"name": "hub已删", "access_token": "keep", "user_id": "9"},
	], ensure_ascii=False), encoding="utf-8")
	return tmp_path


def hub_data(**overrides):
	"""标准输入：demo-com 一个已有账号(token 变了) + 一个新账号；new-site 两个账号。"""
	data = {
		"demo-com": {
			"1": {"name": "老账号", "token": "NEW", "label": "Demo", "domain": "https://demo.com"},
			"2": {"name": "新账号", "token": "T2", "label": "Demo", "domain": "https://demo.com"},
		},
		"new-site-io": {
			"7": {"name": "甲", "token": "T7", "label": "新站", "domain": "https://new-site.io"},
			"8": {"name": "乙", "token": "T8", "label": "新站", "domain": "https://new-site.io"},
		},
		"agentrouter-org": {
			"99": {"name": "不应导入", "token": "TX", "label": "AgentRouter", "domain": "https://agentrouter.org"},
		},
	}
	data.update(overrides)
	return data


def test_新站点追加且不碰已有站点(sandbox):
	merge_import(hub_data(), sandbox)
	sites = json.loads((sandbox / "newapi_sites.json").read_text(encoding="utf-8"))
	ids = [s["id"] for s in sites]
	assert ids == ["demo-com", "claude-x", "new-site-io"], '已有站点与顺序不动，新站点追加尾部'
	new = sites[-1]
	assert new["domain"] == "https://new-site.io" and new["label"] == "新站"
	assert new["accounts_file"] == "new-site-io_accounts.json"
	accs = json.loads((sandbox / "new-site-io_accounts.json").read_text(encoding="utf-8"))
	assert [a["user_id"] for a in accs] == ["7", "8"]


def test_已有站点按userid合并_token变更更新_新账号追加(sandbox):
	merge_import(hub_data(), sandbox)
	accs = {a["user_id"]: a for a in json.loads((sandbox / "demo_accounts.json").read_text(encoding="utf-8"))}
	assert accs["1"]["access_token"] == "NEW", '已有账号 token 变化视为重新登录，就地更新'
	assert accs["2"]["access_token"] == "T2"
	assert "9" in accs, 'hub 侧已删的本地账号保留（可能在别的设备登录）'


def test_保留auto_checkin与历史文件名映射(sandbox):
	merge_import(hub_data(), sandbox)
	sites = {s["id"]: s for s in json.loads((sandbox / "newapi_sites.json").read_text(encoding="utf-8"))}
	assert sites["demo-com"]["auto_checkin"] is False
	assert sites["demo-com"]["accounts_file"] == "demo_accounts.json", '不得改成默认命名'


def test_agentrouter域跳过(sandbox):
	merge_import(hub_data(), sandbox)
	assert not (sandbox / "agentrouter-org_accounts.json").exists()
	sites = [s["id"] for s in json.loads((sandbox / "newapi_sites.json").read_text(encoding="utf-8"))]
	assert "agentrouter-org" not in sites


def test_重复导入幂等(sandbox):
	merge_import(hub_data(), sandbox)
	before = (sandbox / "new-site-io_accounts.json").read_text(encoding="utf-8")
	out = merge_import(hub_data(), sandbox)  # 第二次应报「无变化」且文件不动
	assert out == 0
	assert (sandbox / "new-site-io_accounts.json").read_text(encoding="utf-8") == before
	sites = json.loads((sandbox / "newapi_sites.json").read_text(encoding="utf-8"))
	assert len(sites) == 3, '不得重复追加注册表'


def test_域名保留原始url_连字符域名不被反推破坏(sandbox):
	data = {"grok-heavy-878-indevs-in": {
		"3": {"name": "a", "token": "T", "label": "GN", "domain": "https://grok-heavy.878.indevs.in"},
	}}
	merge_import(data, sandbox)
	sites = {s["id"]: s for s in json.loads((sandbox / "newapi_sites.json").read_text(encoding="utf-8"))}
	assert sites["grok-heavy-878-indevs-in"]["domain"] == "https://grok-heavy.878.indevs.in", \
		'域名含连字符时不能用 sid 反推（会把 grok-heavy 变成 grok.heavy）'


def test_site_id_from_url():
	assert site_id_from_url("https://demo.com") == "demo-com"
	assert site_id_from_url("https://grok-heavy.878.indevs.in/x") == "grok-heavy-878-indevs-in"
