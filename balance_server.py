"""
AnyRouter 余额查询服务
使用 FastAPI + curl_cffi（模拟 Chrome TLS 指纹 + 求解 acw_sc__v2 挑战）绕过阿里云 WAF 查询账号余额
"""

import asyncio
import base64
import contextlib
import hmac
import json
import os
import random
import re
import smtplib
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from pathlib import Path
from urllib.parse import quote, urlparse


import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

# ===== 基础设施与配置（已迁至 server/config.py / server/common.py）=====
# 常量与无状态工具的唯一住所迁移至 server 包；此处重导出保持 bs.<名字> 兼容
# （测试 patch bs.X / 域模块过渡期读 bs.X 均继续有效）。config 导入即加载 .env。
from server.config import (  # noqa: E402
	_LOCAL_PROXY,
	_PROXY,
	_AGENTROUTER_PROXY,
	USER_AGENT,
	CONFIG_FILE,
	NEW_ACCOUNTS_FILE,
	USAGE_FILE,
	AGENTROUTER_ACCOUNTS_FILE,
	CHECKIN_STATE_FILE,
	ANYROUTER_CHECKIN_STATE_FILE,
	CHECKIN_SETTINGS_FILE,
	NEWAPI_SITES_FILE,
	MIHOMO_CONFIG_FILE,
	MIHOMO_GROUP,
	MIHOMO_NODE_SKIP,
	KEYS_CACHE_FILE,
	AGENTROUTER_SESSION_FILE,
	CHECKIN_MIN_DELAY,
	CHECKIN_MAX_DELAY,
	WAF_CACHE_TTL,
	ANYROUTER_CONCURRENCY,
	NEWAPI_CONCURRENCY,
	TOKEN_LIST_PATH,
	TOKEN_PAGE_SIZE,
	KEYS_CACHE_MAX_AGE,
	AGENTROUTER_SESSION_TTL,
)

# ===== 防护/打码/通知（已迁至 server/protection.py、server/turnstile.py、server/notify.py）=====
# 过渡期约定：域模块函数体内晚绑定 bs.<名字>；这里重导出保持 bs.<名字> 兼容。
from server.protection import (  # noqa: E402
	_WAF_CHALLENGE_RE,
	_ESA_DENY_RE,
	_WAF_POS,
	_WAF_MASK,
	_solve_acw_sc_v2,
	_CF_CHALLENGE_BODY_RE,
	_ALIYUN_WAF_COOKIE_NAMES,
	protection_cache,
	_protection_locks,
	get_flaresolverr_url,
	detect_protection,
	solve_aliyun_waf,
	solve_cf_challenge,
	ensure_protection_cookies,
	probe_page_protection,
	protection_test,
	protection_router,
)
from server.turnstile import (  # noqa: E402
	TURNSTILE_SOLVER_PRESETS,
	_TURNSTILE_SOLVER_SEM,
	TURNSTILE_SOLVER_POLL_INTERVAL,
	TURNSTILE_SOLVER_TIMEOUT,
	get_turnstile_solver_config,
	solve_turnstile_token,
	_solve_turnstile_token_raw,
	_solver_stats,
	_solver_stats_bump,
	TurnstileSolverRequest,
	solver_stats,
	solver_balance,
	turnstile_solver_status,
	save_turnstile_solver,
	test_turnstile_solver,
	turnstile_router,
)
from server.notify import (  # noqa: E402
	get_notify_config,
	notify_configured,
	send_webhook_notify,
	_mask_secret,
	get_notify,
	save_notify,
	test_notify,
	NotifyRequest,
	notify_router,
)
from server.common import (  # noqa: E402
	_atomic_write_json,
	_read_json_cached,
	_read_json_models,
	_background_tasks,
	_spawn,
	_UPSTREAM_POOL,
	_get_cffi_session,
)


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI):
	"""应用生命周期。startup 逻辑在文件尾部的 startup_event() 里（此处引用后定义的函数没问题，
	真正执行时机是事件循环启动后）。@app.on_event('startup') 已弃用，统一走 lifespan。
	"""
	await startup_event()
	yield


app = FastAPI(title='New API Balance Manager', lifespan=_lifespan)
app.include_router(protection_router)
app.include_router(turnstile_router)
app.include_router(notify_router)

# 认证配置：从环境变量或 .env 读取（.env 已被 gitignore，别提交真实密码）。
# 未设置 AUTH_PASSWORD 时自动生成随机密码写回 .env —— 开箱即用且每次部署都不同。
AUTH_USERNAME = os.environ.get('AUTH_USERNAME') or 'admin'
AUTH_PASSWORD = os.environ.get('AUTH_PASSWORD') or ''

# 书签采集密钥：/api/collect 的防滥用口令（登录后从「站点管理」复制书签脚本时内嵌）
# 未设置时采集端点禁用
COLLECT_KEY = os.environ.get('COLLECT_KEY') or ''
if not AUTH_PASSWORD:
	AUTH_PASSWORD = uuid.uuid4().hex + uuid.uuid4().hex[:8]
	try:
		with (Path(__file__).parent / '.env').open('a', encoding='utf-8') as f:
			f.write(f'\nAUTH_PASSWORD={AUTH_PASSWORD}\n')
		print(f'[AUTH] .env 未设置 AUTH_PASSWORD，已自动生成并写入 .env（密码看 .env 文件，别让它进日志）。用户名: {AUTH_USERNAME}')
	except OSError:
		print(f'[AUTH] 未设置 AUTH_PASSWORD 且 .env 不可写，本次使用随机密码（重启会变）: {AUTH_PASSWORD}')
TOKEN_EXPIRE_SECONDS = 2592000  # 30 天

active_tokens: dict = {}


class LoginRequest(BaseModel):
	username: str
	password: str


@app.post('/api/login')
async def login(req: LoginRequest):
	# hmac.compare_digest 常数时间比较，消除密码校验的时序侧信道
	if not hmac.compare_digest(req.username.encode(), AUTH_USERNAME.encode()) or not hmac.compare_digest(
		req.password.encode(), AUTH_PASSWORD.encode()
	):
		return {'success': False, 'message': '用户名或密码错误'}
	token = str(uuid.uuid4())
	active_tokens[token] = time.time() + TOKEN_EXPIRE_SECONDS
	return {'success': True, 'token': token}


@app.post('/api/logout')
async def logout(request: Request):
	auth_header = request.headers.get('Authorization', '')
	if auth_header.startswith('Bearer '):
		token = auth_header[7:]
		active_tokens.pop(token, None)
	return {'success': True}


@app.get('/api/check-auth')
async def check_auth(request: Request):
	auth_header = request.headers.get('Authorization', '')
	if not auth_header.startswith('Bearer '):
		return {'authenticated': False}
	token = auth_header[7:]
	expire_time = active_tokens.get(token)
	if not expire_time or time.time() > expire_time:
		active_tokens.pop(token, None)
		return {'authenticated': False}
	return {'authenticated': True}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
	path = request.url.path
	# /api/collect 免登录：书签脚本在站点页面上下文调用，靠 COLLECT_KEY 防滥用
	if path in ('/', '/api/login', '/api/logout', '/api/check-auth', '/api/collect') or not path.startswith('/api'):
		return await call_next(request)
	auth_header = request.headers.get('Authorization', '')
	if not auth_header.startswith('Bearer '):
		return JSONResponse(status_code=401, content={'success': False, 'error': '未登录'})
	token = auth_header[7:]
	expire_time = active_tokens.get(token)
	if not expire_time or time.time() > expire_time:
		active_tokens.pop(token, None)
		return JSONResponse(status_code=401, content={'success': False, 'error': '登录已过期'})
	return await call_next(request)




# ========== AgentRouter 登录域（已迁至 server/agentrouter.py） ==========
# 过渡期约定同前：域模块函数体内晚绑定 bs.<名字>；登录端点暂留主文件（块E 收口）。
# _agentrouter_session/_agentrouter_key_sessions 暂居 server/keys.py，块E 归并到本域。
from server.agentrouter import (  # noqa: E402
	agentrouter_block_reason,
	checkin_gap_seconds,
	LoginAccountItem,
	agentrouter_real_balance,
	query_balance_login,
	sign_in_login,
	load_login_accounts,
	add_checkin_log,
	save_checkin_state,
	load_checkin_state,
	run_login_checkin,
	start_login_checkin,
	_session_expiry_info,
	_FATAL_LOGIN_MARKS,
	_login_balance_one,
	_run_with_rotation,
	_query_login_balances,
	_sign_in_one,
)



ANYROUTER_CONFIG = {
	'domain': 'https://anyrouter.top',
	'login_path': '/login',
	'user_info_path': '/api/user/self',
	'sign_in_path': '/api/user/sign_in',
	'api_user_key': 'new-api-user',
	'waf_cookie_names': ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'],
}

AGENTROUTER_ORG_CONFIG = {
	'domain': 'https://agentrouter.org',
	'login_path': '/api/user/login?turnstile=',
	'user_info_path': '/api/user/self',
	'sign_in_path': '/api/user/sign_in',
}

# ========== 通用 new-api 站点 ==========
# gorouter.app / tabitoken.com 这类站点跑的都是较新版 new-api，接口完全同构，只有域名不同，
# 所以不再为每个站点写一份代码，而是由 newapi_sites.json 驱动。与 anyrouter 的差异（均已实测）：
#   1. 签到接口是 POST /api/user/checkin（旧的 /api/user/sign_in 返回 404），奖励区间由站点配置
#   2. GET /api/user/checkin 额外返回签到配置与历史（enabled / min_quota / max_quota / stats）
#   3. 站点在 Cloudflare 后而非阿里云盾，无需 WAF cookies、无需代理、无需 TLS 指纹
#   4. access_token 可直接签到（anyrouter 的签到只认 session cookie）
#   5. POST 挂了 Cloudflare Turnstile 中间件时，服务器侧要带 ?turnstile=<token> 才签得了：
#      配置了打码平台（saved_config.json 的 turnstile_solver 段）就自动代解，没配置则提示
#      走浏览器脚本；GET 没挂中间件，随时可读状态
#      （见 new-api 的 router/api-router.go：POST 带 middleware.TurnstileCheck()，GET 不带）
# AnyRouter 与 AgentRouter 不在此列：前者要过阿里云 WAF + 走代理，后者只能账号密码登录。

# 首次运行时写入 newapi_sites.json 的内容。gorouter 的数据文件名沿用历史命名，
# 这样升级到通用实现后旧账号与签到状态原地可用，不需要迁移。
NEWAPI_SEED_SITES = [
	{
		'id': 'gorouter',
		'label': 'GoRouter',
		'domain': 'https://gorouter.app',
		'accent': 'orange',
		'accounts_file': 'gorouter_accounts.json',
		'state_file': 'gorouter_checkin_state.json',
	},
	{
		'id': 'tabitoken',
		'label': 'TaBiAI',
		'domain': 'https://tabitoken.com',
		'accent': 'sky',
	},
]





# ========== mihomo 代理域（已迁至 server/mihomo.py） ==========
# 过渡期约定同前：域模块函数体内晚绑定 bs.<名字>；_exit_generation/_ar_session_key
# 因 global 原地递增的耦合关系整体随域迁移，不经 bs.（bs 无读取方）。
from server.mihomo import (  # noqa: E402
	_ar_session_key,
	WAF_PASS_CACHE_TTL,
	_waf_pass_cache,
	_balances_query_lock,
	_mihomo_controller,
	_mihomo_call,
	_query_egress_ip,
	_probe_exit_passes_waf,
	_MihomoGroupSwitcher,
	ExitRotator,
	_KeysExitRotator,
)

# 出口代数计数器：mihomo.ExitRotator 递增、_ar_session_key 读取；测试观察/重绑，家在 bs
_exit_generation = 0

# WAF 轮换 pacing（消费方：_run_with_rotation / 登录余额流，暂留本模块，块D2 随域迁出）
WAF_BATCH_SIZE = 4  # 单个出口 IP 每轮最多查几个（实测 ~8 个触发滑块，留余量给重试）
WAF_ROUND_GAP = 4  # 换了新出口 IP 时，轮与轮之间的间隔秒数
WAF_DEGRADED_GAP = 20  # 没有轮换可用（同 IP 硬扛）时的间隔秒数
WAF_IP_BUDGET = 6  # 单个出口 IP 在整轮查询里的请求预算（实测 ~8 触发滑块）
WAF_COOLDOWN = 45  # 所有出口 IP 都花光预算时的冷却秒数（等 WAF 计数窗口滑过）
WAF_MAX_ATTEMPTS = 3  # 单个账号最多尝试次数（cookie 被滑块标记后要重登，反复被拦就放弃）
WAF_DEADLINE = 420  # 整轮查询的时长上限（秒），超时把剩余账号报错返回
WAF_ABORT_STREAK = 8  # 连续这么多个账号被拦且零成功就提前中止：再打只是给惩罚窗口续命






class TokenAccountItem(BaseModel):
	"""传统 access_token 方式（new_accounts_config.json）"""
	name: str
	access_token: str
	user_id: str


class CollectRequest(BaseModel):
	"""书签脚本上报的账号信息（方案 A：登录站点后一键采集 token）"""

	site_url: str
	access_token: str
	user_id: str = ''
	name: str = ''
	key: str = ''


# ── 站点健康状态（三态：ok / invalid / unknown）────────────────────────
_SITE_STATUS_FILE = Path(__file__).parent / 'site_status.json'
_site_status: dict[str, dict] = {}


def _load_site_status() -> None:
	global _site_status
	try:
		_site_status = json.loads(_SITE_STATUS_FILE.read_text(encoding='utf-8'))
	except Exception:
		_site_status = {}


def _set_site_status(site_id: str, status: str, error: str = '') -> None:
	_site_status[site_id] = {'status': status, 'error': error, 'checked_at': int(time.time())}
	try:
		_SITE_STATUS_FILE.write_text(json.dumps(_site_status, ensure_ascii=False, indent=2), encoding='utf-8')
	except Exception:
		pass


_load_site_status()


# ========== 通用 new-api 站点域（已迁至 server/sites.py） ==========
# 过渡期约定同前：域模块函数体内晚绑定 bs.<名字>；站点端点暂留主文件（块E 收口）。
from server.sites import (  # noqa: E402
	NEWAPI_DEFAULTS,
	NewapiAccountItem,
	NewapiSite,
	newapi_checkin_states,
	load_newapi_sites,
	save_newapi_sites,
	get_newapi_site,
	load_newapi_accounts,
	save_newapi_accounts,
	_newapi_headers,
	newapi_request,
	_proxied_newapi_request,
	query_balance_newapi,
	newapi_turnstile_status,
	sign_in_newapi,
	newapi_checkin_info,
	newapi_state,
	add_newapi_checkin_log,
	save_newapi_checkin_state,
	load_newapi_checkin_state,
	run_newapi_checkin,
	start_newapi_checkin,
	_newapi_checkin_status_payload,
	run_site_patrol,
	site_patrol_scheduler,
	SITE_PATROL_INTERVAL,
	SITE_PATROL_FIRST_DELAY,
	SITE_PATROL_FAIL_LIMIT,
)

# 巡检失败计数（测试会整体重绑，故家在 bs；sites.run_site_patrol 经 bs. 读写）
site_patrol_fails: dict[str, int] = {}






# ========== 余额监控（已迁至 server/monitor.py） ==========
# 过渡期约定同 server/keys.py：模块不做模块级 import balance_server，monitor_state 与
# 跨实体引用在函数体内晚绑定 bs.<名字>。EmailConfig / MonitorStartRequest 随域迁移
# （pydantic 注解在定义期求值，必须与模型同模块）。
from server.monitor import (  # noqa: E402
	EmailConfig,
	MonitorStartRequest,
	monitor_state,
	_collect_monitor_accounts,
	add_monitor_log,
	send_alert_email,
	_monitor_alert_key,
	monitor_loop,
	monitor_router,
)
app.include_router(monitor_router)

# ========== Cookie 域（已迁至 server/cookies.py） ==========
# 过渡期约定同前：域模块函数体内晚绑定 bs.<名字>；cookie 相关端点暂留主文件（块E 收口）。
from server.cookies import (  # noqa: E402
	AccountItem,
	waf_cache,
	_waf_lock,
	ANYROUTER_CONFIG,
	_api_url,
	anyrouter_request,
	anyrouter_block_reason,
	_get_waf_cookies_if_needed,
	get_waf_cookies,
	_query_balance_impl,
	query_balance,
	query_balance_with_token,
	_sign_in_impl,
	sign_in,
	sign_in_with_token,
	load_cookie_accounts,
	_session_is_authenticated,
	save_renewed_sessions,
	renew_one_cookie,
	add_anyrouter_checkin_log,
	save_anyrouter_checkin_state,
	load_anyrouter_checkin_state,
	run_anyrouter_checkin,
	start_anyrouter_checkin,
	cookies_router,
)
app.include_router(cookies_router)


# ========== 每日自动签到开关 ==========
# AgentRouter / cookie 账号是否开启每日 0 点自动签到（持久化到 checkin_settings.json）。
# 通用 new-api 站点的开关不在这里，而是各站点配置里的 auto_checkin，以免新增站点还要改这个字典。
checkin_settings: dict = {
	'agentrouter_auto': True,
	'agentrouter_gap_min': 30,  # 缓慢签到模式：账号间隔下限（分钟）
	'agentrouter_gap_max': 60,  # 缓慢签到模式：账号间隔上限（分钟）
	'anyrouter_auto': True,
}


def load_checkin_settings():
	"""从 checkin_settings.json 恢复自动签到开关；文件不存在则保持默认（都开启）。

	历史上 gorouter 的开关也存在这个文件里（键 `gorouter_auto`），改成通用站点后它归入
	newapi_sites.json 的 auto_checkin，这里做一次性迁移，避免用户之前关掉的开关被悄悄打开。
	"""
	if not CHECKIN_SETTINGS_FILE.exists():
		return
	try:
		data = json.loads(CHECKIN_SETTINGS_FILE.read_text(encoding='utf-8'))
		for k in checkin_settings:
			if isinstance(data.get(k), bool):
				checkin_settings[k] = data[k]
			elif isinstance(data.get(k), int) and not isinstance(data.get(k), bool):
				checkin_settings[k] = data[k]
		legacy = {k[: -len('_auto')]: v for k, v in data.items() if k.endswith('_auto') and k not in checkin_settings}
		if legacy:
			sites = load_newapi_sites()
			changed = False
			for s in sites:
				if s.id in legacy and isinstance(legacy[s.id], bool) and s.auto_checkin != legacy[s.id]:
					s.auto_checkin = legacy[s.id]
					changed = True
			if changed:
				save_newapi_sites(sites)
				print(f'[CHECKIN] 已把旧的自动签到开关迁移到 newapi_sites.json: {legacy}')
		# 迁移完就把旧键去掉，避免每次启动都覆盖站点里的新值
		_atomic_write_json(CHECKIN_SETTINGS_FILE, checkin_settings, indent=2)
	except Exception as e:
		print(f'[CHECKIN] 自动签到设置读取失败: {e}')


def save_checkin_settings():
	"""持久化自动签到开关"""
	try:
		_atomic_write_json(CHECKIN_SETTINGS_FILE, checkin_settings, indent=2)
	except Exception as e:
		print(f'[CHECKIN] 自动签到设置保存失败: {e}')


async def daily_checkin_scheduler():
	"""每日 0 点自动启动 AgentRouter（Login）+ cookie 账号 + 所有通用 new-api 站点的签到。

	AgentRouter/cookie 账号受 checkin_settings 控制，new-api 站点受各自的 auto_checkin 控制；
	关闭后仅跳过自动触发，手动签到不受影响。新增站点会自动纳入，无需改这里。
	"""
	while True:
		try:
			wait_seconds = seconds_until_midnight()
			print(f'[CHECKIN] 下次自动签到将在 {wait_seconds:.0f} 秒后启动')
			await asyncio.sleep(wait_seconds + 10)  # 多等 10 秒确保过了 0 点
			if checkin_settings['agentrouter_auto']:
				if not checkin_state['running']:
					start_login_checkin(trigger='auto')
			else:
				print('[CHECKIN] AgentRouter 每日自动签到已关闭，跳过')
			if checkin_settings['anyrouter_auto']:
				if not anyrouter_checkin_state['running']:
					start_anyrouter_checkin(trigger='auto')
			else:
				print('[ANYROUTER] cookie 账号每日自动签到已关闭，跳过')
			for site in load_newapi_sites():
				if not site.auto_checkin:
					print(f'[{site.id.upper()}] {site.label} 每日自动签到已关闭，跳过')
					continue
				if not newapi_state(site)['running']:
					start_newapi_checkin(site, trigger='auto')
		except Exception as e:
			# 调度器是长生命周期任务：单轮出错只记日志，绝不能让异常杀死整个循环
			print(f'[CHECKIN] 签到调度出错（下一轮继续）: {e}')
			await asyncio.sleep(60)

class QueryRequest(BaseModel):
	accounts: list[AccountItem]


class TokenQueryRequest(BaseModel):
	accounts: list[TokenAccountItem]


# Login 账号签到调度状态（内存 + 持久化到 checkin_state.json）
checkin_state: dict = {
	'running': False,  # 是否正在执行签到流程
	'task': None,  # asyncio.Task
	'date': None,  # 本轮签到所属日期 YYYY-MM-DD
	'started_at': None,  # 本轮开始时间
	'finished_at': None,  # 本轮结束时间
	'trigger': None,  # 触发方式：manual / auto
	'mode': None,  # 本轮模式：slow（默认，逐个间隔签）/ fast（出口轮换批量签）；进骨架才能随状态文件持久化
	'total': 0,  # 账号总数
	'done': 0,  # 已处理数（含成功/失败）
	'order': [],  # 本轮随机顺序的账号名
	'current': None,  # 当前正在签到的账号名
	'next_at': None,  # 下一个账号预计签到时间
	'accounts': {},  # name -> {status: pending|signed|already|failed, message, time}
	'logs': [],  # 最近的签到日志
}

# AnyRouter（cookie/session 方式）签到状态，与上面的 agentrouter 签到完全独立
anyrouter_checkin_state: dict = {
	'running': False,
	'task': None,
	'date': None,
	'started_at': None,
	'finished_at': None,
	'trigger': None,
	'total': 0,
	'signed': 0,
	'already': 0,
	'failed': 0,
	'accounts': {},  # name -> {status: pending|signed|already|failed, message, time}
	'logs': [],
}



def _blank_checkin_state() -> dict:
	"""一个空的签到状态骨架（通用 new-api 站点用）"""
	return {
		'running': False,
		'task': None,
		'date': None,
		'started_at': None,
		'finished_at': None,
		'trigger': None,
		'total': 0,
		'signed': 0,
		'already': 0,
		'failed': 0,
		'accounts': {},  # name -> {status: pending|signed|already|failed, message, time}
		'logs': [],
	}


# ── 签到状态的通用操作 ──
# AgentRouter / AnyRouter / 各 new-api 站点三套签到状态机的日志、持久化、恢复逻辑完全同构，
# 差异只有「状态字典、文件路径、日志前缀」三元组，统一在这里实现，各站点的同名函数只是薄封装。


def _checkin_add_log(st: dict, tag: str, msg: str):
	"""添加签到日志到状态字典，最多保留 100 条"""
	ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	st['logs'].append({'time': ts, 'message': msg})
	if len(st['logs']) > 100:
		st['logs'] = st['logs'][-100:]
	print(f'[{tag} {ts}] {msg}')


def _checkin_save(st: dict, path: Path, tag: str):
	"""持久化签到状态到文件（排除不可序列化的 task）"""
	try:
		data = {k: v for k, v in st.items() if k != 'task'}
		_atomic_write_json(path, data, indent=2)
	except Exception as e:
		print(f'[{tag}] 状态保存失败: {e}')


def _checkin_load(st: dict, path: Path, tag: str):
	"""服务启动时从文件恢复签到状态（仅用于前端展示历史进度），并强制复位运行标记"""
	if not path.exists():
		return
	try:
		data = json.loads(path.read_text(encoding='utf-8'))
		for k, v in data.items():
			if k in st and k != 'task':
				st[k] = v
		# 重启后不可能仍在运行，强制复位运行标记与进度指针
		st['running'] = False
		st['task'] = None
		if 'current' in st:
			st['current'] = None
		if 'next_at' in st:
			st['next_at'] = None
	except Exception as e:
		print(f'[{tag}] 状态恢复失败: {e}')




# ── 前端入口 ────────────────────────────────────────────────────────────────
# frontend/ 是 Vite + React 工程，构建产物落在 frontend/dist/。
# 有构建产物就服务它，没有就回退到 templates/index.html（旧的单文件前端），
# 这样没装 Node 的环境 clone 下来依然开箱即用。
FRONTEND_DIST = Path(__file__).parent / 'frontend' / 'dist'
LEGACY_INDEX = Path(__file__).parent / 'templates' / 'index.html'


def frontend_index() -> Path | None:
	"""当前该用哪个前端入口。构建产物优先，其次旧前端，都没有则 None。

	每次调用都重新判断（不缓存）—— 这样 `pnpm build` 完不必重启服务，
	与旧前端「改完刷新即可」的开发体验保持一致。
	"""
	dist_index = FRONTEND_DIST / 'index.html'
	if dist_index.is_file():
		return dist_index
	if LEGACY_INDEX.is_file():
		return LEGACY_INDEX
	return None


@app.get('/', response_class=HTMLResponse)
async def index():
	entry = frontend_index()
	if entry is None:
		return HTMLResponse(
			'<h1>前端资源缺失</h1><p>既没有 <code>frontend/dist/index.html</code>，'
			'也没有 <code>templates/index.html</code>。</p>'
			'<p>请在 <code>frontend/</code> 下执行 <code>pnpm install &amp;&amp; pnpm build</code>。</p>',
			status_code=503,
		)
	# no-cache：每次都向服务器确认入口有没有更新。部署换版本后浏览器立刻拿新
	# index.html，不会攥着旧产物的 hash 清单去请求已不存在的 chunk
	return HTMLResponse(entry.read_text(encoding='utf-8'), headers={'Cache-Control': 'no-cache'})


@app.get('/api/config')
async def get_config():
	"""读取保存的配置"""
	if CONFIG_FILE.exists():
		try:
			return {'success': True, 'data': _read_json_cached(CONFIG_FILE)}
		except Exception as e:
			return {'success': False, 'error': str(e)}
	return {'success': True, 'data': None}


@app.post('/api/config')
async def save_config(req: dict):
	"""保存配置"""
	try:
		_atomic_write_json(CONFIG_FILE, req, indent=2)
		return {'success': True}
	except Exception as e:
		return {'success': False, 'error': str(e)}


@app.post('/api/query')
async def query(req: QueryRequest):
	"""批量查询账号余额"""
	waf_cookies = await _get_waf_cookies_if_needed()
	if not waf_cookies :
		return {'success': False, 'error': 'WAF cookies 获取失败，请稍后重试'}

	sem = asyncio.Semaphore(ANYROUTER_CONCURRENCY)

	async def limited_query(acc):
		async with sem:
			return await query_balance(acc, waf_cookies)

	tasks = [limited_query(acc) for acc in req.accounts]
	results = await asyncio.gather(*tasks)

	total_quota = sum(r.get('quota', 0) for r in results if r.get('success'))
	total_used = sum(r.get('used', 0) for r in results if r.get('success'))

	return {
		'success': True,
		'results': results,
		'summary': {
			'total_quota': round(total_quota, 2),
			'total_used': round(total_used, 2),
			'account_count': len(results),
			'success_count': sum(1 for r in results if r.get('success')),
		},
	}


@app.post('/api/checkin')
async def checkin(req: QueryRequest):
	"""批量签到"""
	waf_cookies = await _get_waf_cookies_if_needed()
	if not waf_cookies :
		return {'success': False, 'error': 'WAF cookies 获取失败，请稍后重试'}

	sem = asyncio.Semaphore(ANYROUTER_CONCURRENCY)

	async def limited_sign_in(acc):
		async with sem:
			return await sign_in(acc, waf_cookies)

	tasks = [limited_sign_in(acc) for acc in req.accounts]
	results = await asyncio.gather(*tasks)

	success_count = sum(1 for r in results if r.get('success'))
	new_sign_count = sum(1 for r in results if r.get('success') and not r.get('already_signed'))

	return {
		'success': True,
		'results': results,
		'summary': {
			'total': len(results),
			'success': success_count,
			'new_signed': new_sign_count,
		},
	}


# ========== Access Token 方式的接口 ==========


@app.get('/api/token/accounts')
async def get_token_accounts():
	"""获取 new_accounts_config.json 中的账号列表（含完整信息，用于管理）"""
	accounts = load_token_accounts()
	return {
		'success': True,
		'accounts': [acc.model_dump() for acc in accounts],
	}


@app.post('/api/token/accounts')
async def save_token_accounts(req: dict):
	"""保存 token 账号列表到 new_accounts_config.json"""
	try:
		raw_accounts = req.get('accounts', [])
		validated = [TokenAccountItem(**acc) for acc in raw_accounts]
		_atomic_write_json(NEW_ACCOUNTS_FILE, [acc.model_dump() for acc in validated], indent=2)
		return {'success': True}
	except Exception as e:
		return {'success': False, 'error': str(e)}


@app.post('/api/token/query')
async def query_with_token(req: TokenQueryRequest | None = None):
	"""使用 access_token 批量查询账号余额
	如果不传 accounts，则从 new_accounts_config.json 读取
	"""
	if req and req.accounts:
		accounts = req.accounts
	else:
		accounts = load_token_accounts()
		if not accounts:
			return {'success': False, 'error': 'new_accounts_config.json 不存在或为空'}

	waf_cookies = await _get_waf_cookies_if_needed()
	if not waf_cookies :
		return {'success': False, 'error': 'WAF cookies 获取失败，请稍后重试'}

	sem = asyncio.Semaphore(ANYROUTER_CONCURRENCY)

	async def limited_query(acc):
		async with sem:
			return await query_balance_with_token(acc, waf_cookies)

	tasks = [limited_query(acc) for acc in accounts]
	results = await asyncio.gather(*tasks)

	total_quota = sum(r.get('quota', 0) for r in results if r.get('success'))
	total_used = sum(r.get('used', 0) for r in results if r.get('success'))

	return {
		'success': True,
		'results': results,
		'summary': {
			'total_quota': round(total_quota, 2),
			'total_used': round(total_used, 2),
			'account_count': len(results),
			'success_count': sum(1 for r in results if r.get('success')),
		},
	}


@app.post('/api/token/checkin')
async def checkin_with_token(req: TokenQueryRequest | None = None):
	"""使用 access_token 批量签到
	如果不传 accounts，则从 new_accounts_config.json 读取
	"""
	if req and req.accounts:
		accounts = req.accounts
	else:
		accounts = load_token_accounts()
		if not accounts:
			return {'success': False, 'error': 'new_accounts_config.json 不存在或为空'}

	waf_cookies = await _get_waf_cookies_if_needed()
	if not waf_cookies :
		return {'success': False, 'error': 'WAF cookies 获取失败，请稍后重试'}

	sem = asyncio.Semaphore(ANYROUTER_CONCURRENCY)

	async def limited_sign_in(acc):
		async with sem:
			return await sign_in_with_token(acc, waf_cookies)

	tasks = [limited_sign_in(acc) for acc in accounts]
	results = await asyncio.gather(*tasks)

	success_count = sum(1 for r in results if r.get('success'))
	new_sign_count = sum(1 for r in results if r.get('success') and not r.get('already_signed'))

	return {
		'success': True,
		'results': results,
		'summary': {
			'total': len(results),
			'success': success_count,
			'new_signed': new_sign_count,
		},
	}


# ========== Login 方式的接口（agentrouter.org）==========


@app.get('/api/login-accounts/accounts')
async def get_login_accounts():
	"""获取 agentrouter_accounts.json 中的账号列表"""
	accounts = load_login_accounts()
	return {'success': True, 'accounts': [acc.model_dump() for acc in accounts]}


@app.post('/api/login-accounts/accounts')
async def save_login_accounts(req: dict):
	"""保存登录方式账号列表"""
	try:
		raw_accounts = req.get('accounts', [])
		validated = [LoginAccountItem(**acc) for acc in raw_accounts]
		_atomic_write_json(AGENTROUTER_ACCOUNTS_FILE, [acc.model_dump() for acc in validated], indent=2)
		return {'success': True}
	except Exception as e:
		return {'success': False, 'error': str(e)}


@app.post('/api/login-accounts/query')
async def query_login_accounts():
	"""查询所有 agentrouter.org 账号余额"""
	accounts = load_login_accounts()
	if not accounts:
		return {'success': False, 'error': 'agentrouter_accounts.json 不存在或为空'}

	# 登录接口有按 IP 限流，顺序处理并在账号之间加延迟以规避 429
	results = []
	for i, acc in enumerate(accounts):
		if i > 0:
			await asyncio.sleep(1.5)
		results.append(await query_balance_login(acc))
	total_quota = sum(r.get('quota', 0) for r in results if r.get('success'))
	total_used = sum(r.get('used', 0) for r in results if r.get('success'))
	return {
		'success': True,
		'results': results,
		'summary': {
			'total_quota': round(total_quota, 2),
			'total_used': round(total_used, 2),
			'account_count': len(results),
			'success_count': sum(1 for r in results if r.get('success')),
		},
	}


@app.post('/api/login-accounts/checkin/fast')
async def login_checkin_fast():
	"""一键全签：轮换出口 IP 分批登录（agentrouter 登录即签到），约 1~2 分钟跑完。

	与 /checkin/start 的缓慢模式（账号间隔默认 30~60 分钟，可在设置里改）互补。
	出口轮换是全局动作，与余额查询共用一把锁；今天已签到的账号直接跳过，省 WAF 配额。
	"""
	accounts = load_login_accounts()
	if not accounts:
		return {'success': False, 'error': 'agentrouter_accounts.json 不存在或为空'}
	if checkin_state['running']:
		return {'success': False, 'error': '签到流程正在运行（缓慢模式不可打断），请先停止或等它结束'}
	if _balances_query_lock.locked():
		return {'success': False, 'error': '已有一轮出口轮换任务（余额查询/全签到）在进行中，请等它结束再点'}

	# 今天已签到的账号跳过：登录即签到，已签过再登一次既没意义又白耗 WAF 配额
	today = datetime.now().strftime('%Y-%m-%d')
	done_status: dict = {}
	if checkin_state.get('date') == today:
		done_status = {
			n: v
			for n, v in (checkin_state.get('accounts') or {}).items()
			if v.get('status') in ('signed', 'already')
		}
	pending = [a for a in accounts if a.name not in done_status]

	checkin_state.update(
		running=True,
		date=today,
		trigger='fast',
		mode='fast',
		started_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
		finished_at=None,
		total=len(accounts),
		done=len(done_status),
		order=[a.name for a in accounts],
		current=None,
		next_at=None,
		logs=[],
	)
	checkin_state['accounts'] = {
		a.name: done_status.get(a.name) or {'status': 'pending', 'message': '等待签到', 'time': None}
		for a in accounts
	}
	add_checkin_log(f'一键全签开始（轮换出口）：{len(pending)} 个待签 / {len(done_status)} 个今日已签跳过')
	save_checkin_state()

	def _on_result(account, r):
		ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		if r.get('success'):
			checkin_state['accounts'][account.name] = {
				'status': 'already' if r.get('already_signed') else 'signed',
				'message': r.get('message', '签到成功'),
				'time': ts,
				'quota': r.get('quota'),
				'used': r.get('used'),
			}
			# 登录响应顺带拿到的余额写进今日快照（quota 为 None 说明没取到，跳过记账）
			if r.get('quota') is not None:
				record_account_usage('agentrouter', account.name, r.get('used', 0), r.get('quota', 0))
			add_checkin_log(f'{account.name}: {r.get("message", "签到成功")}')
		else:
			msg = r.get('error') or r.get('message') or '签到失败'
			checkin_state['accounts'][account.name] = {'status': 'failed', 'message': msg, 'time': ts}
			add_checkin_log(f'{account.name}: 签到失败 — {msg}')
		checkin_state['done'] = sum(
			1 for v in checkin_state['accounts'].values() if v.get('status') in ('signed', 'already', 'failed')
		)
		save_checkin_state()

	results: list = []
	aborted = False
	if pending:
		async with _balances_query_lock:
			# 停止按钮置 running=False，轮换调度每轮开始前检查它 —— fast 模式从此可停
			results, aborted = await _run_with_rotation(
				pending, _sign_in_one, on_result=_on_result, should_stop=lambda: not checkin_state['running']
			)
	else:
		add_checkin_log('全部账号今日都已签到，无需签到')

	stopped = not checkin_state['running']  # 停止按钮已把 running 置 False
	checkin_state['running'] = False
	checkin_state['finished_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	signed = sum(1 for v in checkin_state['accounts'].values() if v.get('status') in ('signed', 'already'))
	failed = sum(1 for v in checkin_state['accounts'].values() if v.get('status') == 'failed')
	add_checkin_log(
		f'一键全签结束：{signed}/{checkin_state["total"]} 已签到，失败 {failed}'
		+ ('（WAF 惩罚期提前中止）' if aborted else '')
		+ ('（手动停止）' if stopped else '')
	)
	save_checkin_state()
	return {
		'success': True,
		'summary': {
			'total': len(accounts),
			'new_signed': sum(1 for r in results if r.get('success') and not r.get('already_signed')),
			'already': sum(1 for r in results if r.get('already_signed')) + len(done_status),
			'failed': failed,
			'aborted': aborted,
		},
		'status': _checkin_status_payload(),
	}


@app.post('/api/login-accounts/checkin/start')
async def login_checkin_start():
	"""启动 Login 账号签到流程（随机顺序、账号间随机等待 30~60 分钟）"""
	if checkin_state['running']:
		return {'success': False, 'error': '签到流程已在运行中', 'status': _checkin_status_payload()}
	accounts = load_login_accounts()
	if not accounts:
		return {'success': False, 'error': 'agentrouter_accounts.json 不存在或为空'}
	start_login_checkin(trigger='manual')
	# 稍等片刻让任务初始化状态
	await asyncio.sleep(0.2)
	return {'success': True, 'message': f'签到流程已启动，共 {len(accounts)} 个账号', 'status': _checkin_status_payload()}


@app.post('/api/login-accounts/checkin/stop')
async def login_checkin_stop():
	"""停止正在运行的 Login 账号签到流程"""
	if not checkin_state['running']:
		return {'success': False, 'error': '当前没有正在运行的签到流程'}
	checkin_state['running'] = False
	add_checkin_log('收到停止指令')
	return {'success': True, 'message': '已发送停止指令'}


def _checkin_status_payload() -> dict:
	"""组装签到状态返回体"""
	accounts = [
		{
			'name': name,
			'status': info.get('status', 'pending'),
			'message': info.get('message', ''),
			'time': info.get('time'),
			'quota': info.get('quota'),
			'used': info.get('used'),
		}
		for name, info in checkin_state['accounts'].items()
	]
	# 按本轮随机顺序排序，便于前端展示进度
	order_index = {n: i for i, n in enumerate(checkin_state['order'])}
	accounts.sort(key=lambda a: order_index.get(a['name'], 999))
	signed = sum(1 for a in accounts if a['status'] in ('signed', 'already'))
	failed = sum(1 for a in accounts if a['status'] == 'failed')
	# done = 已到达终态（成功/今日已签/最终失败）的账号数；pending（含待重试）不计
	done = signed + failed
	return {
		'running': checkin_state['running'],
		'date': checkin_state['date'],
		'trigger': checkin_state['trigger'],
		'mode': checkin_state.get('mode') or 'slow',
		'started_at': checkin_state['started_at'],
		'finished_at': checkin_state['finished_at'],
		'total': checkin_state['total'],
		'done': done,
		'signed': signed,
		'failed': failed,
		'current': checkin_state['current'],
		'next_at': checkin_state['next_at'],
		'accounts': accounts,
		'logs': checkin_state['logs'][-30:],
	}


@app.get('/api/login-accounts/checkin/status')
async def login_checkin_status():
	"""获取 Login 账号签到流程的进度状态"""
	return {'success': True, 'status': _checkin_status_payload()}


def _all_checkin_settings() -> dict:
	"""把 AnyRouter/AgentRouter 的开关与各 new-api 站点的 auto_checkin 合成一份扁平设置。

	站点开关对外也叫 `<site_id>_auto`，与前两者同形，前端只需一套逻辑；
	真实存储位置不同（前两者在 checkin_settings.json，站点在 newapi_sites.json）。
	"""
	merged = dict(checkin_settings)
	for s in load_newapi_sites():
		merged[f'{s.id}_auto'] = s.auto_checkin
	return merged


@app.get('/api/checkin/settings')
async def get_checkin_settings():
	"""获取每日自动签到开关（含各 new-api 站点）"""
	return {'success': True, 'settings': _all_checkin_settings()}


@app.post('/api/checkin/settings')
async def update_checkin_settings(req: dict):
	"""更新每日自动签到开关与缓慢签到间隔（仅影响 0 点自动触发，手动签到始终可用）"""
	changed = []
	gap_keys = ('agentrouter_gap_min', 'agentrouter_gap_max')
	for k in checkin_settings:
		if k in gap_keys:
			continue  # 这两个是数字（分钟），走下面的间隔处理，别被当布尔开关
		if isinstance(req.get(k), bool) and req[k] != checkin_settings[k]:
			checkin_settings[k] = req[k]
			changed.append(f'{k}={req[k]}')
	# 缓慢签到的间隔范围（分钟）：夹到 1~1440，填反了自动对调
	for k in gap_keys:
		v = req.get(k)
		if isinstance(v, bool) or not isinstance(v, int):
			continue
		clamped = min(1440, max(1, v))
		if clamped != checkin_settings[k]:
			checkin_settings[k] = clamped
			changed.append(f'{k}={clamped}')
	if checkin_settings['agentrouter_gap_min'] > checkin_settings['agentrouter_gap_max']:
		checkin_settings['agentrouter_gap_min'], checkin_settings['agentrouter_gap_max'] = (
			checkin_settings['agentrouter_gap_max'], checkin_settings['agentrouter_gap_min'])
		changed.append(f"间隔范围对调为 {checkin_settings['agentrouter_gap_min']}~{checkin_settings['agentrouter_gap_max']} 分钟")
	if changed:
		save_checkin_settings()
	# new-api 站点的开关落在 newapi_sites.json
	sites = load_newapi_sites()
	site_changed = False
	for s in sites:
		key = f'{s.id}_auto'
		if isinstance(req.get(key), bool) and req[key] != s.auto_checkin:
			s.auto_checkin = req[key]
			site_changed = True
			changed.append(f'{key}={req[key]}')
	if site_changed:
		save_newapi_sites(sites)
	if changed:
		print(f'[CHECKIN] 自动签到设置已更新: {", ".join(changed)}')
	return {'success': True, 'settings': _all_checkin_settings()}


# ==== AgentRouter 余额查询的出口 IP 轮换 ====
# 阿里云 WAF 对 agentrouter 的拦截（2026-08-22 实测）：同一出口 IP 连续 ~8 个 /api/user/self
# 触发滑块页；**吃过滑块页的 session cookie 换到任何 IP 依旧被拦，重登换新 cookie 立即恢复**；
# 被拦后快速重试还会升级成丢包（连接超时）。应对：ExitRotator 查询期间轮换 mihomo 出口
# （切到能过 WAF 的节点、结束后恢复原节点 —— 期间经 7890 的其它流量出口会跟着变），每轮每 IP 只查
# WAF_BATCH_SIZE 个账号，被拦的下一轮换 IP 重登再试。



@app.get('/api/login-accounts/balances')
async def login_accounts_balances(live: bool = False, names: str = ''):
	"""返回每个 agentrouter（Login）账号的余额。

	复用缓存 session 只打 /api/user/self；`live=true` 强制全部重登；`names=a,b` 只查指定账号
	（按名字精确匹配，逗号分隔）。结果写进今日快照当基线，今日用量从第二次查询起就能算出来。

	因为 WAF 按出口 IP + cookie 拦截（见 ExitRotator 的注释），这里不能全量并发：
	_query_login_balances 分批轮换出口 IP，一轮全量约 1~2 分钟。轮换是全局动作，
	同一时刻只允许一轮查询（重复点击会收到「查询进行中」）。
	"""
	accounts = load_login_accounts()
	if names:
		wanted = {n.strip() for n in names.split(',') if n.strip()}
		accounts = [a for a in accounts if a.name in wanted]
	if not accounts:
		return {
			'success': True,
			'results': [],
			'summary': {'total_quota': 0, 'total_used': 0, 'account_count': 0, 'success_count': 0},
		}
	if _balances_query_lock.locked():
		return {'success': False, 'error': '已有一轮 AgentRouter 查询在进行中（要轮换出口 IP，必须独占），请等它结束再点'}
	async with _balances_query_lock:
		results = await _query_login_balances(accounts, live)
	for r in results:
		if r.get('success'):
			record_account_usage('agentrouter', r['name'], r['used'], r['quota'])
	failed = sum(1 for r in results if not r.get('success'))
	if failed:
		print(f'[AGENTROUTER] 余额查询：{failed}/{len(results)} 个账号失败')
	total_quota = sum(r['quota'] for r in results if r.get('success'))
	total_used = sum(r['used'] for r in results if r.get('success'))
	return {
		'success': True,
		'results': results,
		'summary': {
			'total_quota': round(total_quota, 2),
			'total_used': round(total_used, 2),
			'account_count': len(results),
			'success_count': len(results) - failed,
		},
	}


# ========== AnyRouter（cookie）签到与续期接口 ==========


@app.post('/api/anyrouter/checkin/start')
async def anyrouter_checkin_start():
	"""启动 AnyRouter cookie 账号签到（并发，数秒完成）"""
	if anyrouter_checkin_state['running']:
		return {'success': False, 'error': 'AnyRouter 签到已在运行中', 'status': _anyrouter_checkin_status_payload()}
	accounts = load_cookie_accounts()
	if not accounts:
		return {'success': False, 'error': '没有 cookie 账号可签到'}
	start_anyrouter_checkin(trigger='manual')
	await asyncio.sleep(0.2)
	return {
		'success': True,
		'message': f'AnyRouter 签到已启动，共 {len(accounts)} 个账号',
		'status': _anyrouter_checkin_status_payload(),
	}


@app.get('/api/anyrouter/checkin/status')
async def anyrouter_checkin_status():
	"""获取 AnyRouter 签到进度状态"""
	return {'success': True, 'status': _anyrouter_checkin_status_payload()}


@app.get('/api/anyrouter/cookie-status')
async def anyrouter_cookie_status():
	"""返回每个 cookie 账号 session 的过期时间与剩余天数"""
	accounts = load_cookie_accounts()
	items = []
	for a in accounts:
		info = _session_expiry_info(a.cookies.get('session', '')) or {}
		items.append({
			'name': a.name,
			'api_user': a.api_user,
			'expires_at': info.get('expires_at'),
			'days_left': info.get('days_left'),
		})
	return {'success': True, 'accounts': items}


@app.post('/api/anyrouter/renew')
async def anyrouter_renew(req: dict | None = None):
	"""续期 AnyRouter cookie 账号的 session（+30 天）。

	可传 {"names": [...]} 指定账号，不传则续期全部 cookie 账号。
	续期成功的新 session 会写回 saved_config.json。

	一旦某个账号撞上 ESA 的 IP 限流就中止后续账号：限的是出口 IP，剩下的账号必然同样失败，
	白打几十个请求还可能把限流窗口续上（计数器是否随新请求延长未实测，但没有理由去试）。
	实测触发后至少半小时内所有 anyrouter 功能全废。
	"""
	accounts = load_cookie_accounts()
	if not accounts:
		return {'success': False, 'error': '没有 cookie 账号'}
	if req and req.get('names'):
		wanted = set(req['names'])
		accounts = [a for a in accounts if a.name in wanted]
		if not accounts:
			return {'success': False, 'error': '指定的账号不存在'}

	waf_cookies = await _get_waf_cookies_if_needed()
	if not waf_cookies:
		return {'success': False, 'error': 'WAF cookies 获取失败，请稍后重试'}

	sem = asyncio.Semaphore(ANYROUTER_CONCURRENCY)
	ratelimited = asyncio.Event()

	def _skipped(name: str) -> dict:
		return {'name': name, 'success': False, 'message': '已跳过：站点正在限流，本轮提前中止', 'skipped': True}

	async def _limited(a):
		if ratelimited.is_set():
			return _skipped(a.name)
		async with sem:
			# 再判一次：排队等信号量的这段时间里，前面的账号可能已经撞上限流
			if ratelimited.is_set():
				return _skipped(a.name)
			r = await renew_one_cookie(a, waf_cookies)
		if r.get('blocked') == 'ratelimit':
			ratelimited.set()
		return r

	results = await asyncio.gather(*[_limited(a) for a in accounts])
	# 写回续期成功的新 session
	updates = {r['name']: r['new_session'] for r in results if r.get('success') and r.get('new_session')}
	save_renewed_sessions(updates)
	# 返回时剔除敏感的 new_session 字段
	clean = [{k: v for k, v in r.items() if k != 'new_session'} for r in results]
	skipped = sum(1 for r in results if r.get('skipped'))
	payload = {
		'success': True,
		'results': clean,
		'summary': {
			'total': len(results),
			'renewed': sum(1 for r in results if r.get('success')),
			'failed': sum(1 for r in results if not r.get('success')),
			'skipped': skipped,
		},
	}
	if ratelimited.is_set():
		payload['notice'] = (
			f'站点限流已触发，本轮中止（跳过 {skipped} 个账号）。这是按出口 IP 的临时封禁，'
			'期间余额查询与签到也会失败。请隔一段时间再点续期 —— 反复重试会让封禁持续更久。'
		)
	return payload


# ========== 通用 new-api 站点接口 ==========
# 路径里的 {site_id} 对应 newapi_sites.json 里的 id。加站点不需要新增路由。


def _site_or_error(site_id: str) -> tuple[NewapiSite | None, dict | None]:
	"""取站点配置，找不到时返回统一的错误体"""
	site = get_newapi_site(site_id)
	if site is None:
		return None, {'success': False, 'error': f'站点 {site_id} 不存在'}
	return site, None


@app.get('/api/sites')
async def get_sites(with_counts: bool = False):
	"""返回所有通用 new-api 站点配置，附带三态健康状态

	with_counts=true 时附带各站点账号数（站点管理页用）——读盘走 mtime 缓存，
	顺带返回比前端对每个站点各发一次 /site/{id}/accounts 便宜得多。
	"""
	sites = load_newapi_sites()
	resp: dict = {
		'success': True,
		'sites': [
			{**s.model_dump(), 'status': _site_status.get(s.id, {'status': 'unknown', 'error': ''})}
			for s in sites
		],
		'collect_key_ready': bool(COLLECT_KEY),
	}
	if with_counts:
		resp['counts'] = {s.id: len(load_newapi_accounts(s)) for s in sites}
	return resp


@app.get('/api/collect/key')
async def collect_key():
	"""返回书签采集密钥（前端生成书签脚本用），未启用时返回空"""
	return {'success': True, 'key': COLLECT_KEY}


def _token_rejected(status: int, body: str) -> bool:
	"""识别 new-api 的 token 拒绝响应：401/403、正文含「无权」，或 4xx 且正文提到 token。

	只认 4xx：5xx/限流页正文也常带 "token" 字样，不能据此判 token 无效。
	"""
	return status in (401, 403) or '无权' in body or ('token' in body.lower() and 400 <= status < 500)


async def _collect_anyrouter_token(req: CollectRequest) -> dict:
	"""anyrouter.top 的采集：验证后写入 new_accounts_config.json（provider=anyrouter）"""
	headers = {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': ANYROUTER_CONFIG['domain'],
		'Origin': ANYROUTER_CONFIG['domain'],
		'Authorization': f'Bearer {req.access_token}',
		ANYROUTER_CONFIG['api_user_key']: req.user_id or '0',
	}
	try:
		resp = await anyrouter_request('GET', _api_url(ANYROUTER_CONFIG['user_info_path']), headers)
		body = resp.text or ''
		status = resp.status_code
	except Exception as e:
		return {'success': False, 'error': f'验证请求异常: {type(e).__name__}: {str(e)[:80]}'}

	if _token_rejected(status, body):
		return {'success': False, 'error': f'token 无效（HTTP {status}）'}

	try:
		data = json.loads(body)
	except Exception:
		return {'success': False, 'error': f'站点返回非 JSON（HTTP {status}）'}

	if isinstance(data, dict) and data.get('success') is False:
		msg = str(data.get('error') or data.get('message') or '未知错误')[:100]
		return {'success': False, 'error': f'站点拒绝: {msg}'}

	inner = data.get('data', {}) if isinstance(data, dict) else {}
	user_id = str(req.user_id or inner.get('id') or data.get('id') or '')
	if not user_id:
		return {'success': False, 'error': '未能从响应取到 user id，请确认账号有效后重试'}

	username = inner.get('username') or data.get('username') or req.name or 'user'
	accounts = load_token_accounts()
	replaced = any(a.user_id == user_id or a.name == username for a in accounts)
	accounts = [a for a in accounts if a.user_id != user_id and a.name != username]
	accounts.append(TokenAccountItem(name=username, access_token=req.access_token, user_id=user_id, provider='anyrouter'))
	_atomic_write_json(NEW_ACCOUNTS_FILE, [a.model_dump() for a in accounts], indent=2)
	_set_site_status('anyrouter', 'ok', '')
	return {'success': True, 'message': f'AnyRouter 账号 {username} 已更新（{"覆盖" if replaced else "新增"}）'}


@app.options('/api/collect')
async def collect_preflight(request: Request):
	"""CORS 预检：书签脚本从站点页面跨域调用，需放行"""
	return Response(
		status_code=204,
		headers={
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type',
			'Access-Control-Max-Age': '86400',
		},
	)


@app.post('/api/collect')
async def collect_token(req: CollectRequest, request: Request):
	"""书签脚本采集端点：按 site_url 匹配站点，验证 token 后写入配置。

	书签脚本运行在站点页面上下文（可读该站 localStorage），因此需要 CORS 放行；
	`key` 与 COLLECT_KEY 一致才接受（防他人往配置里塞 token）。
	"""
	# CORS：预检与真实请求都放行（仅此端点）
	origin = request.headers.get('origin', '*')
	if request.method == 'OPTIONS':
		return Response(
			status_code=204,
			headers={
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Methods': 'POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type',
				'Access-Control-Max-Age': '86400',
			},
		)

	if not COLLECT_KEY:
		return JSONResponse(
			status_code=503,
			content={'success': False, 'error': '采集功能未启用（服务器未配置 COLLECT_KEY）'},
			headers={'Access-Control-Allow-Origin': origin},
		)
	if not req.key or not hmac.compare_digest(req.key, COLLECT_KEY):
		return JSONResponse(
			status_code=401,
			content={'success': False, 'error': '采集密钥无效'},
			headers={'Access-Control-Allow-Origin': origin},
		)

	site = next(
		(s for s in load_newapi_sites() if s.domain.rstrip('/') == req.site_url.rstrip('/')),
		None,
	)
	if site is None:
		# anyrouter.top 是专用账号（provider=anyrouter，存 new_accounts_config.json），单独处理
		if req.site_url.rstrip('/') == ANYROUTER_CONFIG['domain']:
			return await _collect_anyrouter_token(req)
		return {'success': False, 'error': f'站点 {req.site_url} 未接入（先在「站点管理」添加）'}

	# 验证 token：带 Chrome 指纹调 user/self
	verify_account = NewapiAccountItem(name='__verify__', access_token=req.access_token, user_id=req.user_id or '')
	try:
		resp = await anyrouter_request('GET', f'{site.domain}{site.user_info_path}', _newapi_headers(site, verify_account))
		body = resp.text or ''
		status = resp.status_code
	except Exception as e:
		_set_site_status(site.id, 'invalid', f'验证请求异常: {type(e).__name__}')
		return {'success': False, 'error': f'验证请求异常: {type(e).__name__}: {str(e)[:80]}'}

	if _token_rejected(status, body):
		_set_site_status(site.id, 'invalid', f'HTTP {status}')
		return {'success': False, 'error': f'token 无效（HTTP {status}）'}

	try:
		data = json.loads(body)
	except Exception:
		_set_site_status(site.id, 'invalid', f'响应非 JSON（HTTP {status}）')
		return {'success': False, 'error': f'站点返回非 JSON（HTTP {status}），可能被风控拦截'}

	if isinstance(data, dict) and data.get('success') is False:
		msg = str(data.get('error') or data.get('message') or '未知错误')[:100]
		_set_site_status(site.id, 'invalid', msg)
		return {'success': False, 'error': f'站点拒绝: {msg}'}

	# new-api 的 user/self 返回 {success, data: {id, username, ...}}，id 在 data 里
	inner = data.get('data', {}) if isinstance(data, dict) else {}
	user_id = str(req.user_id or inner.get('id') or data.get('id') or '')
	if not user_id:
		return {'success': False, 'error': '未能从响应取到 user id，请确认账号有效后重试'}

	# 写入配置：同名或同 user_id 覆盖，否则追加
	accounts = load_newapi_accounts(site)
	username = inner.get('username') or inner.get('display_name') or req.name or 'user'
	name = username
	existing = [a for a in accounts if a.user_id == user_id or a.name == name]
	replaced = bool(existing)
	if existing:
		accounts = [a for a in accounts if a not in existing]
	accounts.append(NewapiAccountItem(name=name, access_token=req.access_token, user_id=user_id))
	save_newapi_accounts(site, accounts)
	_set_site_status(site.id, 'ok', '')
	return {
		'success': True,
		'message': f'{site.label} 账号 {name} 已更新（{"覆盖" if replaced else "新增"}）',
	}


@app.post('/api/sites')
async def save_sites(req: dict):
	"""保存站点清单。前端「站点管理」用它增删改站点，后端无需改代码即可支持新站点。

	删除站点时保留其账号文件与签到状态文件，避免误删后账号丢失（重新添加同 id 即可恢复）。
	"""
	try:
		raw = req.get('sites', [])
		validated = [NewapiSite(**s) for s in raw]
		ids = [s.id for s in validated]
		if len(set(ids)) != len(ids):
			return {'success': False, 'error': '站点 id 重复'}
		for s in validated:
			if not s.id.replace('_', '').replace('-', '').isalnum():
				return {'success': False, 'error': f'站点 id 只能用字母数字与 -_：{s.id}'}
			if not s.domain.startswith('http'):
				return {'success': False, 'error': f'域名要带 http(s)://：{s.domain}'}
			s.domain = s.domain.rstrip('/')
		save_newapi_sites(validated)
		return {'success': True, 'sites': [s.model_dump() for s in validated]}
	except Exception as e:
		return {'success': False, 'error': str(e)}


@app.post('/api/sites/probe')
async def probe_site(req: dict):
	"""探测一个域名是否是 new-api 站点，供前端在添加前确认域名填对了。

	读 `GET /api/status`：能返回 `data.version` 就是 new-api，顺带把站点名、签到是否开启、
	Turnstile 状态、quota 换算单位一并回给前端做默认值。此接口不写任何文件。
	"""
	domain = (req.get('domain') or '').strip().rstrip('/')
	if not domain.startswith('http'):
		return {'success': False, 'error': '域名要带 http(s)://'}
	probe = NewapiSite(id='__probe__', label='probe', domain=domain)
	try:
		resp = await newapi_request(probe, 'GET', probe.status_path, {'User-Agent': USER_AGENT})
	except Exception as e:
		return {'success': False, 'error': f'{type(e).__name__}: {e}'[:150]}
	if resp.status_code != 200:
		return {'success': False, 'error': f'HTTP {resp.status_code}'}
	try:
		data = (resp.json() or {}).get('data', {}) or {}
	except Exception:
		return {'success': False, 'error': '返回的不是 JSON，可能不是 new-api 站点'}
	if not data.get('version'):
		return {'success': False, 'error': '未识别为 new-api 站点（/api/status 里没有 version）'}
	page = await probe_page_protection(domain)
	return {
		'success': True,
		'info': {
			'version': data.get('version'),
			'system_name': data.get('system_name') or '',
			'checkin_enabled': bool(data.get('checkin_enabled')),
			'turnstile_check': bool(data.get('turnstile_check')),
			'quota_per_unit': data.get('quota_per_unit') or NEWAPI_DEFAULTS['quota_per_unit'],
			'protections': {
				'cf_challenge': bool(page.get('cf_challenge')),
				'aliyun_waf': bool(page.get('aliyun_waf')),
			},
		},
	}


@app.get('/api/site/{site_id}/accounts')
async def get_site_accounts(site_id: str):
	"""获取某站点的账号列表"""
	site, err = _site_or_error(site_id)
	if err:
		return err
	return {'success': True, 'accounts': [a.model_dump() for a in load_newapi_accounts(site)]}


@app.post('/api/site/{site_id}/accounts')
async def post_site_accounts(site_id: str, req: dict):
	"""保存某站点的账号列表"""
	site, err = _site_or_error(site_id)
	if err:
		return err
	try:
		validated = [NewapiAccountItem(**acc) for acc in req.get('accounts', [])]
		save_newapi_accounts(site, validated)
		return {'success': True}
	except Exception as e:
		return {'success': False, 'error': str(e)}


@app.post('/api/site/{site_id}/query')
async def query_site(site_id: str):
	"""批量查询某站点账号余额（并发，无 WAF/代理依赖）"""
	site, err = _site_or_error(site_id)
	if err:
		return err
	accounts = load_newapi_accounts(site)
	if not accounts:
		return {'success': False, 'error': f'没有 {site.label} 账号'}

	sem = asyncio.Semaphore(site.concurrency or NEWAPI_CONCURRENCY)

	async def _limited(a):
		async with sem:
			return await query_balance_newapi(site, a)

	results = await asyncio.gather(*[_limited(a) for a in accounts])
	ok = [r for r in results if r.get('success')]
	if ok:
		_set_site_status(site.id, 'ok', '')
	else:
		errors = '; '.join(str(r.get('error', ''))[:60] for r in results if not r.get('success'))
		_set_site_status(site.id, 'invalid', errors[:200])
	return {
		'success': True,
		'results': results,
		'summary': {
			'total_quota': round(sum(r['quota'] for r in ok), 2),
			'total_used': round(sum(r['used'] for r in ok), 2),
			'account_count': len(results),
			'success_count': len(ok),
		},
	}


@app.post('/api/site/{site_id}/checkin/start')
async def site_checkin_start(site_id: str):
	"""启动某站点的账号签到（并发，数秒完成）"""
	site, err = _site_or_error(site_id)
	if err:
		return err
	st = newapi_state(site)
	if st['running']:
		return {'success': False, 'error': f'{site.label} 签到已在运行中', 'status': _newapi_checkin_status_payload(site)}
	accounts = load_newapi_accounts(site)
	if not accounts:
		return {'success': False, 'error': f'没有 {site.label} 账号可签到'}
	start_newapi_checkin(site, trigger='manual')
	await asyncio.sleep(0.2)
	return {
		'success': True,
		'message': f'{site.label} 签到已启动，共 {len(accounts)} 个账号',
		'status': _newapi_checkin_status_payload(site),
	}


@app.get('/api/site/{site_id}/turnstile')
async def site_turnstile(site_id: str):
	"""返回某站点当前的 Turnstile 状态，供前端决定签到走哪条路。

	enabled=True  → 服务器端要带 token 才签得了：配置了打码平台就自动求解，
	                没配置则前端展示浏览器脚本 + 同步流程
	enabled=False → 站长关掉了校验，前端直接走 /checkin/start 一键签到
	"""
	site, err = _site_or_error(site_id)
	if err:
		return err
	return {'success': True, 'turnstile': await newapi_turnstile_status(site)}


@app.get('/api/site/{site_id}/checkin/status')
async def site_checkin_status(site_id: str):
	"""获取某站点的签到进度状态"""
	site, err = _site_or_error(site_id)
	if err:
		return err
	return {'success': True, 'status': _newapi_checkin_status_payload(site)}


@app.post('/api/site/{site_id}/checkin/sync')
async def site_checkin_sync(site_id: str):
	"""在浏览器脚本签完之后，从站点核对每个账号的真实签到状态。

	`GET /api/user/checkin` 没有挂 Turnstile 中间件（只有 POST 挂了，见 new-api 的
	router/api-router.go），所以服务器随时能读到 `stats.checked_in_today`。用它核对，
	就不需要浏览器脚本把结果回传 —— 脚本跑在站点的 HTTPS 页面上，受混合内容策略
	限制本来也无法 fetch 回 HTTP 的本服务。

	顺便查一次余额写入今日快照，与 run_newapi_checkin 的口径保持一致。
	"""
	site, err = _site_or_error(site_id)
	if err:
		return err
	accounts = load_newapi_accounts(site)
	if not accounts:
		return {'success': False, 'error': f'没有 {site.label} 账号'}

	sem = asyncio.Semaphore(site.concurrency or NEWAPI_CONCURRENCY)
	results: dict = {}

	async def _one(acc: NewapiAccountItem):
		async with sem:
			info = await newapi_checkin_info(site, acc)
			bal = await query_balance_newapi(site, acc)
		if bal.get('success'):
			record_account_usage(site.id, acc.name, bal['used'], bal['quota'])
		if not info.get('success'):
			results[acc.name] = {'name': acc.name, 'success': False, 'message': info.get('error', '状态查询失败')}
			return
		checked = bool(info.get('checked_in_today'))
		results[acc.name] = {
			'name': acc.name,
			'success': checked,
			'message': '今日已签到' if checked else '今日未签到',
			'already_signed': checked,
			'total_checkins': info.get('total_checkins'),
			'quota': bal.get('quota') if bal.get('success') else None,
			'used': bal.get('used') if bal.get('success') else None,
		}

	await asyncio.gather(*[_one(a) for a in accounts])

	ordered = [results[a.name] for a in accounts if a.name in results]
	now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	st = newapi_state(site)
	st['running'] = False
	st['date'] = datetime.now().strftime('%Y-%m-%d')
	st['trigger'] = 'browser'
	st['started_at'] = st.get('started_at') or now_str
	st['finished_at'] = now_str
	st['total'] = len(ordered)
	st['accounts'] = {}
	st['logs'] = []
	for r in ordered:
		st['accounts'][r['name']] = {
			'status': 'already' if r['success'] else 'failed',
			'message': r['message'],
			'time': now_str,
		}
		add_newapi_checkin_log(site, f'{r["name"]}: {r["message"]}')
	signed = sum(1 for r in ordered if r['success'])
	st['signed'] = 0
	st['already'] = signed
	st['failed'] = len(ordered) - signed
	add_newapi_checkin_log(site, f'状态同步完成：已签到 {signed} / {len(ordered)}')
	save_newapi_checkin_state(site)

	return {
		'success': True,
		'results': ordered,
		'checked_in': signed,
		'total': len(ordered),
		'status': _newapi_checkin_status_payload(site),
	}


@app.get('/api/site/{site_id}/checkin/info')
async def site_checkin_info_all(site_id: str):
	"""读取某站点各账号的签到状态与奖励区间（不触发签到）"""
	site, err = _site_or_error(site_id)
	if err:
		return err
	accounts = load_newapi_accounts(site)
	if not accounts:
		return {'success': False, 'error': f'没有 {site.label} 账号'}

	sem = asyncio.Semaphore(site.concurrency or NEWAPI_CONCURRENCY)

	async def _limited(a):
		async with sem:
			return await newapi_checkin_info(site, a)

	results = await asyncio.gather(*[_limited(a) for a in accounts])
	return {'success': True, 'accounts': results}


# ========== 密钥管理（new-api 的「令牌」/api/token/） ==========
# 实现已迁至 server/keys.py（拆分第一块）。过渡期约定：
#   - keys.py 不做模块级 import balance_server（防循环导入），函数体内对账号加载器、
#     请求通道、可变缓存等一切跨实体引用晚绑定 bs.<名字> —— 测试对 bs 命名空间的
#     monkeypatch（resolve_key_ctx / _agentrouter_session / _KeysExitRotator /
#     KEYS_CACHE_FILE 等）因此原样生效，本块迁移零测试改动；
#   - 文件路径常量留在本模块（测试会改写它们指向 tmp）；
#   - 后续域迁移时逐步把 bs.* 换成真正的模块内依赖，patch 目标随之迁移。
TOKEN_LIST_PATH = '/api/token/'
TOKEN_PAGE_SIZE = 100
KEYS_CACHE_FILE = Path(__file__).parent / 'keys_cache.json'
KEYS_CACHE_MAX_AGE = 30 * 24 * 3600  # 保存时清掉一个月没碰过的条目，防无限增长
AGENTROUTER_SESSION_TTL = 6 * 3600
AGENTROUTER_SESSION_FILE = Path(__file__).parent / 'agentrouter_sessions.json'

from server.keys import (  # noqa: E402
	KeyCtx,
	_key_value_cache,
	_keys_list_cache,
	_agentrouter_key_sessions,
	_agentrouter_login_lock,
	_keys_reveal_until,
	_keys_reveal_lock,
	KEYS_REVEAL_CONCURRENCY,
	KEYS_REVEAL_MAX_SWITCHES,
	KEYS_REVEAL_LIMIT_WINDOW,
	load_keys_list_cache,
	save_keys_list_cache,
	load_agentrouter_sessions,
	save_agentrouter_sessions,
	_agentrouter_session,
	resolve_key_ctx,
	_parse_token_items,
	_token_row,
	reveal_key_values,
	list_account_keys,
	_reveal_scope,
	_keys_cache_store_if_complete,
	_reveal_accounts,
	keys_list,
	keys_create,
	keys_delete,
	keys_router,
)
app.include_router(keys_router)




# ========== 每日用量统计（已迁至 server/usage.py） ==========
# 过渡期约定同 server/keys.py：usage.py 不做模块级 import balance_server，跨实体引用
# （USAGE_FILE、账号加载器、余额查询通道）在函数体内晚绑定 bs.<名字>，测试的
# monkeypatch 原样生效；_usage_cache/_usage_cache_path 会被 load/save 重绑，其读写
# 一律走 bs. 保证命名空间唯一事实来源。USAGE_FILE 常量留在本模块（测试会改写）。
from server.usage import (  # noqa: E402
	_usage_cache,
	_usage_cache_path,
	load_usage_data,
	save_usage_data,
	usage_key,
	migrate_usage_keys,
	run_usage_key_migration,
	record_account_usage,
	take_daily_snapshot,
	seconds_until_midnight,
	daily_snapshot_scheduler,
	get_today_usage,
	get_usage_history,
	manual_snapshot,
	usage_router,
)
app.include_router(usage_router)

def load_token_accounts() -> list[TokenAccountItem]:
	"""从 new_accounts_config.json 加载 access_token 账号列表"""
	return _read_json_models(NEW_ACCOUNTS_FILE, TokenAccountItem, 'TOKEN')

async def startup_event():
	"""服务启动时初始化定时任务"""
	# 先把用量快照的 key 迁移成「站点:账号名」，再判断今日有没有快照 —— 顺序反了会用旧 key 判断
	run_usage_key_migration()
	# 恢复 agentrouter 的 session 缓存，避免重启后第一次查余额就是 18 次登录（会被 429）
	load_agentrouter_sessions()
	# 恢复密钥列表缓存：密钥很少变，打开弹窗默认走缓存，零上游请求
	load_keys_list_cache()
	# 如果今天还没有快照，启动时立即执行一次作为基准线
	today = datetime.now().strftime('%Y-%m-%d')
	usage_data = load_usage_data()
	if today not in usage_data:
		print(f'[USAGE] 今日 ({today}) 无快照数据，启动时立即执行快照')
		_spawn(take_daily_snapshot())
	_spawn(daily_snapshot_scheduler())
	print('[USAGE] 每日快照调度器已启动')

	# 恢复 Login 签到状态并启动每日签到调度器
	load_checkin_settings()
	_sites = load_newapi_sites()
	_site_flags = ' '.join(f'{s.label}={"开" if s.auto_checkin else "关"}' for s in _sites)
	print(
		f'[CHECKIN] 自动签到开关: AgentRouter={"开" if checkin_settings["agentrouter_auto"] else "关"} '
		f'AnyRouter={"开" if checkin_settings["anyrouter_auto"] else "关"} {_site_flags}'
	)
	load_checkin_state()
	_spawn(daily_checkin_scheduler())
	print('[CHECKIN] 每日签到调度器已启动')
	# 若今日尚未完成签到（服务在 0 点后才启动，或上一轮被重启中断），立即补一轮
	_accts = checkin_state.get('accounts', {})
	done_today = (
		checkin_state.get('date') == today
		and checkin_state.get('total', 0) > 0
		and len(_accts) >= checkin_state.get('total', 0)
		and all(v.get('status') != 'pending' for v in _accts.values())
	)
	if checkin_settings['agentrouter_auto'] and not done_today and not checkin_state['running']:
		login_accounts = load_login_accounts()
		if login_accounts:
			print(f'[CHECKIN] 今日 ({today}) 签到未完成，启动时补签一轮')
			start_login_checkin(trigger='auto')

	# 恢复 AnyRouter（cookie）签到状态，若今日未完成则补签一轮
	load_anyrouter_checkin_state()
	_a_accts = anyrouter_checkin_state.get('accounts', {})
	a_done_today = (
		anyrouter_checkin_state.get('date') == today
		and anyrouter_checkin_state.get('total', 0) > 0
		and len(_a_accts) >= anyrouter_checkin_state.get('total', 0)
		and all(v.get('status') != 'pending' for v in _a_accts.values())
	)
	if checkin_settings['anyrouter_auto'] and not a_done_today and not anyrouter_checkin_state['running']:
		if load_cookie_accounts():
			print(f'[ANYROUTER] 今日 ({today}) 签到未完成，启动时补签一轮')
			start_anyrouter_checkin(trigger='auto')

	# 恢复各 new-api 站点（token）的签到状态，若今日未完成则补签一轮
	for site in _sites:
		load_newapi_checkin_state(site)
		st = newapi_state(site)
		_s_accts = st.get('accounts', {})
		s_done_today = (
			st.get('date') == today
			and st.get('total', 0) > 0
			and len(_s_accts) >= st.get('total', 0)
			and all(v.get('status') != 'pending' for v in _s_accts.values())
		)
		if site.auto_checkin and not s_done_today and not st['running']:
			if load_newapi_accounts(site):
				print(f'[{site.id.upper()}] 今日 ({today}) 签到未完成，启动时补签一轮')
				start_newapi_checkin(site, trigger='auto')

	# 站点健康自动巡检（6 小时一轮，连续 3 次不可达自动暂停该站签到并推通知）
	_spawn(site_patrol_scheduler())
	print('[PATROL] 站点健康巡检调度器已启动')


# 三个 /api/usage/* 端点已迁至 server/usage.py（usage_router 已在上面 include）

def mask_proxy_url(url: str) -> str:
	"""把代理 URL 里的认证凭据打码。

	代理可能写成 http://user:pass@host:port，原样吐给前端会经由 devtools、
	截图或录屏泄露出去。主机和端口保留 —— 那才是排障要看的东西。

	只在 authority 段（`://` 之后、第一个 `/` 之前）动手，并且按**最后一个** `@`
	切分：密码本身可能含 `@`（`user:p@ssw0rd@host`），按第一个 `@` 切会把
	`ssw0rd` 原样留下 —— 半截密码照样是泄露。host 段不允许出现 `@`，
	所以最后一个 `@` 之前的一律是 userinfo。
	"""
	if not url:
		return ''
	m = re.match(r'^([A-Za-z0-9+.\-]+://)([^/]*)(.*)$', url)
	if not m:
		return url
	scheme, authority, rest = m.groups()
	if '@' in authority:
		authority = '***:***@' + authority.rsplit('@', 1)[1]
	return scheme + authority + rest


async def probe_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
	"""探测 TCP 端口是否可连。用于判断本地代理有没有真的在跑。"""
	try:
		_, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
		writer.close()
		with contextlib.suppress(Exception):
			await writer.wait_closed()
		return True
	except Exception:
		return False


@app.get('/api/system/proxy-info')
async def get_proxy_info(probe: bool = False):
	"""只读展示代理相关配置，供前端「设置」页做诊断。

	这些值来自环境变量 / .env，前端改不了（改完要重启服务），所以纯只读。
	之所以值得暴露：访问 anyrouter / agentrouter 必须走本地代理，代理没起来时
	表现为一句藏在服务端日志里的 `[WAF] Failed to connect to 127.0.0.1:7890`，
	用户在界面上完全看不到，只会觉得"查询莫名其妙失败"。

	带 ?probe=true 时会实际连一下代理端口确认是否在跑。
	"""
	source = 'default'
	if os.environ.get('HTTPS_PROXY'):
		source = 'HTTPS_PROXY'
	elif os.environ.get('HTTP_PROXY'):
		source = 'HTTP_PROXY'

	reachable = None
	if probe:
		parsed = urlparse(_PROXY)
		if parsed.hostname and parsed.port:
			reachable = await probe_tcp(parsed.hostname, parsed.port)

	return {
		'success': True,
		'proxy': {
			'url': mask_proxy_url(_PROXY),
			'source': source,
			'has_credentials': '@' in _PROXY.split('://', 1)[-1].split('/', 1)[0],
			'reachable': reachable,
		},
		'mihomo': {
			'group': MIHOMO_GROUP,
			# 组名为空时不做出口轮换，是有意的安全降级而非故障
			'rotation_enabled': bool(MIHOMO_GROUP),
			'config_path': str(MIHOMO_CONFIG_FILE),
			'config_exists': await asyncio.to_thread(MIHOMO_CONFIG_FILE.is_file),
		},
	}


# ── 前端静态资源与 SPA 路由回退 ──────────────────────────────────────────────
# 必须注册在所有 /api 路由之后：FastAPI 按注册顺序匹配，这个 catch-all 放前面
# 会把所有接口都吃掉。
@app.get('/{full_path:path}')
async def frontend_catch_all(full_path: str):
	"""服务构建产物里的静态文件，其余路径交还给前端路由。

	新前端用 react-router 的 BrowserRouter，/dashboard、/accounts 这类路径在服务端
	并不存在，直接访问或刷新会 404，所以要回退到 index.html 由前端接管。
	"""
	# 未匹配到任何已注册接口的 /api 路径，按 API 语义返回 JSON 而不是 HTML，
	# 否则前端的 fetch 会拿到一坨 HTML 然后在 JSON.parse 处炸掉，难以排查。
	if full_path == 'api' or full_path.startswith('api/'):
		return JSONResponse({'success': False, 'error': f'未知接口: /{full_path}'}, status_code=404)

	# 命中构建产物里的真实文件就直接返回（assets/*.js、favicon 等）
	if FRONTEND_DIST.is_dir():
		candidate = (FRONTEND_DIST / full_path).resolve()
		# 防目录穿越：解析后必须仍在 dist 内
		if candidate.is_file() and candidate.is_relative_to(FRONTEND_DIST.resolve()):
			# assets/ 下是带 content hash 的产物，内容变了文件名必变，可永久缓存
			headers = {'Cache-Control': 'public, max-age=31536000, immutable'} if full_path.startswith('assets/') else None
			return FileResponse(candidate, headers=headers)

	# 长得像静态文件的路径缺了文件就老实 404，绝不能回退 index.html——浏览器会把
	# HTML 当 JS 模块解析，报「Failed to fetch dynamically imported module」，看似
	# 代码坏了，实际是旧标签页在请求旧 hash 的 chunk（部署后尚未刷新的页面）
	last_segment = full_path.rsplit('/', 1)[-1]
	if '.' in last_segment:
		return JSONResponse({'success': False, 'error': f'静态资源不存在: /{full_path}'}, status_code=404)

	entry = frontend_index()
	if entry is None:
		return JSONResponse({'success': False, 'error': '前端资源缺失'}, status_code=503)
	return HTMLResponse(entry.read_text(encoding='utf-8'), headers={'Cache-Control': 'no-cache'})


if __name__ == '__main__':
	uvicorn.run(app, host='0.0.0.0', port=8003)
