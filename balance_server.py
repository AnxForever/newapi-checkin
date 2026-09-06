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

# anyrouter.top 与 agentrouter.org 现均需经本地代理（mihomo 7890）访问，且需浏览器级 TLS 指纹
_LOCAL_PROXY = 'http://127.0.0.1:7890'
_PROXY = os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY') or _LOCAL_PROXY
_AGENTROUTER_PROXY = _LOCAL_PROXY

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel


def _load_dotenv() -> None:
	"""极简 .env 加载：KEY=VALUE 每行一条，# 开头是注释；已存在的环境变量优先于 .env。"""
	env_file = Path(__file__).parent / '.env'
	try:
		for line in env_file.read_text(encoding='utf-8').splitlines():
			line = line.strip()
			if not line or line.startswith('#') or '=' not in line:
				continue
			key, _, value = line.partition('=')
			key, value = key.strip(), value.strip().strip('\'"')
			if key and key not in os.environ:
				os.environ[key] = value
	except OSError:
		pass  # 没有 .env 就全靠环境变量


_load_dotenv()


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI):
	"""应用生命周期。startup 逻辑在文件尾部的 startup_event() 里（此处引用后定义的函数没问题，
	真正执行时机是事件循环启动后）。@app.on_event('startup') 已弃用，统一走 lifespan。
	"""
	await startup_event()
	yield


app = FastAPI(title='New API Balance Manager', lifespan=_lifespan)

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


# ── 通用工具 ────────────────────────────────────────────────────────────────

def _atomic_write_json(path: Path, data, indent: int | None = None) -> None:
	"""原子写 JSON：先写临时文件再 os.replace。

	直接 write_text 覆盖原文件，进程在写入中途崩溃/断电会留下半个 JSON；
	os.replace 在同一文件系统上是原子的，最坏情况也只是旧文件完好无损。
	"""
	tmp = path.with_name(path.name + '.tmp')
	tmp.write_text(json.dumps(data, ensure_ascii=False, indent=indent), encoding='utf-8')
	os.replace(tmp, path)
	# 本进程是这些配置文件唯一的写入方，写完直接丢缓存，下次读按新 mtime 重建
	_json_cache.pop(path, None)


# 配置文件读多写少（几乎每个 API 请求都要 load 一遍账号/站点清单），
# 按 (mtime_ns, size) 缓存解析结果：文件没变就只做一次 stat，不再反复读盘 + json.loads。
# 进程外手动改文件也会因 mtime 变化自动失效。
_json_cache: dict[Path, tuple[tuple[int, int], object]] = {}


def _read_json_cached(path: Path) -> object:
	"""读 JSON 并走 mtime 缓存；文件不存在抛 FileNotFoundError，损坏抛 JSONDecodeError"""
	try:
		st = path.stat()
	except OSError as e:
		_json_cache.pop(path, None)
		raise FileNotFoundError(str(path)) from e
	stamp = (st.st_mtime_ns, st.st_size)
	cached = _json_cache.get(path)
	if cached is not None and cached[0] == stamp:
		return cached[1]
	data = json.loads(path.read_text(encoding='utf-8'))
	_json_cache[path] = (stamp, data)
	return data


def _read_json_models(path: Path, model, tag: str) -> list:
	"""读取「JSON 数组 + pydantic 模型」配置文件的公共样板；文件不存在或损坏都返回空列表"""
	try:
		data = _read_json_cached(path)
		return [model(**item) for item in data]
	except FileNotFoundError:
		return []
	except Exception as e:
		print(f'[{tag}] 加载 {path.name} 失败: {e}')
		return []


# 后台任务强引用：事件循环对 task 只持弱引用，不保存随时可能被 GC 静默杀掉
_background_tasks: set = set()


def _spawn(coro):
	"""create_task 并持有引用，结束后自动清理。所有长生命周期调度器都该走这里。"""
	task = asyncio.create_task(coro)
	_background_tasks.add(task)
	task.add_done_callback(_background_tasks.discard)
	return task


# 配置文件路径
CONFIG_FILE = Path(__file__).parent / 'saved_config.json'
NEW_ACCOUNTS_FILE = Path(__file__).parent / 'new_accounts_config.json'
USAGE_FILE = Path(__file__).parent / 'daily_usage.json'
AGENTROUTER_ACCOUNTS_FILE = Path(__file__).parent / 'agentrouter_accounts.json'
CHECKIN_STATE_FILE = Path(__file__).parent / 'checkin_state.json'
ANYROUTER_CHECKIN_STATE_FILE = Path(__file__).parent / 'anyrouter_checkin_state.json'
CHECKIN_SETTINGS_FILE = Path(__file__).parent / 'checkin_settings.json'
# 通用 new-api 站点注册表。gorouter.app / tabitoken.com 这类同构站点都登记在这里，
# 新增站点只需往这个文件里加一条（前端「站点管理」即可完成），后端无需改代码。
NEWAPI_SITES_FILE = Path(__file__).parent / 'newapi_sites.json'

# Login 账号签到节奏：每个账号之间随机等待 30~60 分钟，避免登录接口按 IP 限流（429）
CHECKIN_MIN_DELAY = 1800  # 30 分钟（默认；实际间隔以 checkin_settings 的 agentrouter_gap_min/max 为准）
CHECKIN_MAX_DELAY = 3600  # 60 分钟


def checkin_gap_seconds() -> int:
	"""缓慢签到模式的账号间隔（秒），范围可由前端设置（分钟）。设置坏了就退回默认 30~60 分钟"""
	try:
		gmin = max(1, int(checkin_settings.get('agentrouter_gap_min')))
		gmax = max(gmin, int(checkin_settings.get('agentrouter_gap_max')))
	except (TypeError, ValueError):
		return random.randint(CHECKIN_MIN_DELAY, CHECKIN_MAX_DELAY)
	return random.randint(gmin, gmax) * 60

# WAF cookies 缓存: {provider: {'cookies': dict, 'expires': float}}
waf_cache: dict = {}
WAF_CACHE_TTL = 300  # 5 分钟

# 阿里云挑战页会把待求解的参数写成 var arg1='...'；ESA 拦截页会写明命中的规则名
_WAF_CHALLENGE_RE = re.compile(r"arg1='([0-9A-Fa-f]+)'")
_ESA_DENY_RE = re.compile(r'Denied by (\w+)')

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
NEWAPI_DEFAULTS = {
	'user_info_path': '/api/user/self',
	'sign_in_path': '/api/user/checkin',
	'status_path': '/api/status',
	'api_user_key': 'new-api-user',
	'quota_per_unit': 500000,
	'concurrency': 10,
	'accent': 'orange',
}

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


USER_AGENT = (
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'
)

# 上游请求专用线程池。curl_cffi 是同步库，靠线程池并发；此前用的是 asyncio 默认线程池，
# 容量固定为 min(32, cpu_count + 4)，本机 4 核 = 8 个 worker，成了真正的瓶颈：
# 实测 162 个请求在 Semaphore=15/池=8 下 14.2s，池放到 20 后 7.5s，光加 Semaphore 无效。
_UPSTREAM_POOL = ThreadPoolExecutor(max_workers=32, thread_name_prefix='upstream')

# 单站并发上限。总并发受线程池 32 约束；AnyRouter 的 token 与 cookie 两类账号会同时查询，
# 因此 12 × 2 = 24 仍在池容量内。Login（agentrouter.org）不在此列——登录接口按 IP 限流。
ANYROUTER_CONCURRENCY = 12
# 通用 new-api 站点的默认并发，可被单个站点配置里的 concurrency 覆盖
NEWAPI_CONCURRENCY = 10

_thread_local = threading.local()


def _get_cffi_session(key: str, proxies: dict | None = None):
	"""取当前线程的 curl_cffi Session（按 key 区分不同站点/代理配置）。

	复用 Session 才能复用代理 CONNECT 隧道与 TLS 握手，实测单请求中位耗时 0.56s → 0.19s。

	注意：curl_cffi 的 Session 会把每次请求传入的 cookies 累积进自己的 jar，并在后续请求中
	继续发送（已实测），而同一个 Session 会被不同账号轮流复用，所以每次取用时必须清空 cookie，
	否则上一个账号的 session cookie 会串到下一个账号的请求上。
	"""
	from curl_cffi import requests as cffi_requests

	pool = getattr(_thread_local, 'sessions', None)
	if pool is None:
		pool = {}
		_thread_local.sessions = pool
	sess = pool.get(key)
	if sess is None:
		sess = cffi_requests.Session(impersonate='chrome131', proxies=proxies, timeout=30)
		pool[key] = sess
	sess.cookies.clear()
	return sess


_exit_generation = 0


def _ar_session_key(base: str) -> str:
	"""agentrouter 专用连接池 key，带出口代数。

	mihomo 切换节点**不会杀掉已建立的 keep-alive 隧道**，复用 Session 会继续从旧出口
	出去（2026-08-22 实测：连切三个节点，复用连接的出口 IP 纹丝不动，新建连接才跟随切换）。
	ExitRotator 每次切换出口把代数 +1 逼请求重新建连 —— 不带代数的话轮换形同虚设，
	所有批次都从第一个出口 IP 出去，那个 IP 的 WAF 预算瞬间打满。
	"""
	return f'{base}:g{_exit_generation}'


class AccountItem(BaseModel):
	"""传统 session cookie 方式"""
	name: str
	cookies: dict
	api_user: str


class TokenAccountItem(BaseModel):
	"""Access Token 方式（来自 new_accounts_config.json）"""
	name: str
	access_token: str
	user_id: str
	provider: str = 'anyrouter'


class LoginAccountItem(BaseModel):
	"""agentrouter.org 账号密码登录方式"""
	name: str
	username: str
	password: str


class NewapiAccountItem(BaseModel):
	"""通用 new-api 站点的 Access Token 账号（来自各站点自己的 accounts_file）"""

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


class NewapiSite(BaseModel):
	"""一个 new-api 同构站点的配置。前端「站点管理」写入 newapi_sites.json，后端据此工作。

	`id` 决定接口路径（/api/site/{id}/...）与数据文件名，创建后不应再改；
	`accounts_file` / `state_file` 允许显式指定，用于兼容 gorouter 的历史文件名。
	"""

	id: str
	label: str
	domain: str
	accent: str = 'orange'
	user_info_path: str = NEWAPI_DEFAULTS['user_info_path']
	sign_in_path: str = NEWAPI_DEFAULTS['sign_in_path']
	status_path: str = NEWAPI_DEFAULTS['status_path']
	api_user_key: str = NEWAPI_DEFAULTS['api_user_key']
	quota_per_unit: int = NEWAPI_DEFAULTS['quota_per_unit']
	concurrency: int = NEWAPI_CONCURRENCY
	auto_checkin: bool = True
	accounts_file: str = ''
	state_file: str = ''

	def accounts_path(self) -> Path:
		return Path(__file__).parent / (self.accounts_file or f'{self.id}_accounts.json')

	def state_path(self) -> Path:
		return Path(__file__).parent / (self.state_file or f'{self.id}_checkin_state.json')


class QueryRequest(BaseModel):
	accounts: list[AccountItem]


class TokenQueryRequest(BaseModel):
	accounts: list[TokenAccountItem]


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

# 通用 new-api 站点的签到状态：site_id -> 状态字典，结构与上面两者一致。
# 各站点互不影响，可同时签到；持久化到各站点自己的 state_file。
newapi_checkin_states: dict[str, dict] = {}


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


def _api_url(path: str) -> str:
	"""返回 API 地址"""
	return ANYROUTER_CONFIG['domain'] + path


async def anyrouter_request(method: str, url: str, headers: dict, cookies: dict | None = None, json_body=None):
	"""向 anyrouter.top 发请求：curl_cffi 模拟 Chrome TLS 指纹 + 走代理（绕过 WAF/TLS 指纹检测）。

	curl_cffi 是同步库，放到专用线程池执行，并按线程复用 Session 以复用代理隧道与 TLS 握手。

	若响应是 WAF 挑战页，就用响应体里新的 arg1 就地重算 acw_sc__v2 再打一次（2026-08-09 实测有效）。
	这比重新走 get_waf_cookies() 少一个请求 —— 请求数直接决定会不会撞上 ESA 的 IP 限流。
	对 POST（签到）重试也是安全的：挑战页由阿里云边缘返回，请求没到过 new-api 源站，不会重复签到。
	返回 curl_cffi 的 Response 对象。
	"""
	proxies = {'https': _LOCAL_PROXY, 'http': _LOCAL_PROXY}
	send = dict(cookies or {})

	def _do(ck: dict):
		sess = _get_cffi_session('anyrouter', proxies)
		return sess.request(method.upper(), url, headers=headers, cookies=ck, json=json_body)

	loop = asyncio.get_running_loop()
	resp = await loop.run_in_executor(_UPSTREAM_POOL, _do, send)
	if resp.status_code != 200:
		return resp
	try:
		m = _WAF_CHALLENGE_RE.search(resp.text or '')
	except Exception:
		return resp
	if not m:
		return resp
	try:
		fresh = _solve_acw_sc_v2(m.group(1))
	except Exception:
		return resp

	# 挑战页可能顺带下发新的 acw_tc/cdn_sec_tc（Max-Age 只有 1 小时，缓存里的可能已过期），
	# 而 acw_sc__v2 是配着它们校验的，所以重试要用挑战页给的新值。只取 WAF 那几个名字，
	# 避免把响应里其它 cookie（如 session）混进来。
	try:
		issued = dict(resp.cookies)
	except Exception:
		issued = {}
	for name in ANYROUTER_CONFIG['waf_cookie_names']:
		if issued.get(name):
			send[name] = issued[name]
	send['acw_sc__v2'] = fresh
	cached = waf_cache.get('anyrouter')
	if cached:
		# 让同一轮里后续账号直接用新值，别再各撞一次挑战页
		for name in ANYROUTER_CONFIG['waf_cookie_names']:
			if send.get(name):
				cached['cookies'][name] = send[name]
	return await loop.run_in_executor(_UPSTREAM_POOL, _do, send)


def anyrouter_block_reason(resp) -> tuple[str, str] | None:
	"""判断 anyrouter.top 的响应是否被拦截，返回 (kind, 人话原因)；正常返回 None。

	kind 有三种：
	  ratelimit — 阿里云 ESA 按出口 IP 限流：403 + 正文写着「Denied by http_ratelimit」、server: ESA。
	              实测与账号、路径、并发度都无关。2026-08-09 一次持续 28 分钟以上，2026-08-10 一次
	              在每 2.5 分钟探一次的情况下超过 30 分钟仍未解除 —— 探测本身也算请求，很可能在给
	              窗口续命。所以对策是**彻底停手等**，别写死"多久恢复"，也别循环重试。
	  challenge — 仍是 WAF 挑战页（正文带 arg1），说明 acw_sc__v2 没带上或算错了。
	  http      — 其它非 200。
	"""
	try:
		body = resp.text or ''
	except Exception:
		body = ''
	if resp.status_code != 200:
		m = _ESA_DENY_RE.search(body)
		if m:
			rule = m.group(1)
			if 'ratelimit' in rule.lower():
				return ('ratelimit', '站点限流：出口 IP 被 ESA 临时封禁，请过一段时间再试，期间不要反复重试')
			return ('http', f'被站点安全策略拦截（ESA {rule}）')
		return ('http', f'HTTP {resp.status_code}')
	if _WAF_CHALLENGE_RE.search(body):
		return ('challenge', 'WAF 挑战未通过：返回的是验证页而非数据')
	return None


async def _get_waf_cookies_if_needed() -> dict:
	"""获取 WAF cookies"""
	cookies = await get_waf_cookies()
	if cookies is None:
		return {}
	return cookies


@app.get('/api/waf/warmup')
async def waf_warmup():
	"""预热 WAF cookies 缓存，前端页面加载时调用"""
	cookies = await get_waf_cookies()
	if cookies:
		return {'success': True, 'message': 'WAF cookies 已就绪'}
	return {'success': False, 'message': 'WAF cookies 获取失败'}


# 阿里云 WAF acw_sc__v2 挑战求解常量（从挑战页混淆脚本反混淆得到，长期稳定）
_WAF_POS = [
	0xF, 0x23, 0x1D, 0x18, 0x21, 0x10, 0x1, 0x26, 0xA, 0x9, 0x13, 0x1F, 0x28, 0x1B, 0x16, 0x17, 0x19, 0xD,
	0x6, 0xB, 0x27, 0x12, 0x14, 0x8, 0xE, 0x15, 0x20, 0x1A, 0x2, 0x1E, 0x7, 0x4, 0x11, 0x5, 0x3, 0x1C, 0x22,
	0x25, 0xC, 0x24,
]
_WAF_MASK = '3000176000856006061501533003690027800375'


def _solve_acw_sc_v2(arg1: str) -> str:
	"""根据挑战页的 arg1 计算阿里云 WAF 的 acw_sc__v2 cookie。

	等价于挑战页混淆脚本：先按 q[i]=arg1[pos[i]-1] 重排，再与 mask 逐字节十六进制异或。
	"""
	q = ''.join(arg1[_WAF_POS[i] - 1] for i in range(len(_WAF_POS)))
	v = ''
	for i in range(0, min(len(q), len(_WAF_MASK)), 2):
		v += format(int(q[i : i + 2], 16) ^ int(_WAF_MASK[i : i + 2], 16), '02x')
	return v


_waf_lock = asyncio.Lock()


async def get_waf_cookies() -> dict | None:
	"""获取 WAF cookies（curl_cffi 求解 acw_sc__v2 挑战），带缓存 + singleflight。

	阿里云 WAF 现已按 TLS 指纹（JA3）拦截无头 Chromium，导致 Playwright 直接握手失败
	（net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH），拿不到 cookie。改用 curl_cffi 模拟
	Chrome 指纹访问登录页，提取 acw_tc/cdn_sec_tc 并解析 arg1 计算 acw_sc__v2 即可通过校验。

	加锁做 singleflight：缓存过期瞬间，warmup/查询/签到等并发调用只放一个去打挑战页，
	其余等结果 —— 挑战页请求是要省着用的配额。
	"""
	cached = waf_cache.get('anyrouter')
	if cached and cached['expires'] > time.time():
		return cached['cookies']

	async with _waf_lock:
		# 双检：排队等锁期间可能已有同伴刷新了缓存
		cached = waf_cache.get('anyrouter')
		if cached and cached['expires'] > time.time():
			return cached['cookies']

		config = ANYROUTER_CONFIG
		login_url = f'{config["domain"]}{config["login_path"]}'
		required = config['waf_cookie_names']

		def _do() -> dict:
			from curl_cffi import requests as cffi_requests

			# 这里刻意新建独立 Session（不复用 _get_cffi_session）：需要一个干净的 cookie jar
			# 来收集登录页下发的 Set-Cookie。每 5 分钟才走一次，握手开销可忽略。
			sess = cffi_requests.Session(
				impersonate='chrome131',
				proxies={'https': _LOCAL_PROXY, 'http': _LOCAL_PROXY},
				timeout=30,
			)
			resp = sess.get(login_url, headers={'User-Agent': USER_AGENT})
			waf_cookies = {}
			for name in required:
				val = sess.cookies.get(name)
				if val:
					waf_cookies[name] = val
			m = _WAF_CHALLENGE_RE.search(resp.text)
			if m:
				waf_cookies['acw_sc__v2'] = _solve_acw_sc_v2(m.group(1))
			return waf_cookies

		try:
			loop = asyncio.get_running_loop()
			waf_cookies = await loop.run_in_executor(_UPSTREAM_POOL, _do)
			if waf_cookies:
				waf_cache['anyrouter'] = {
					'cookies': waf_cookies,
					'expires': time.time() + WAF_CACHE_TTL,
				}
				return waf_cookies
			return None
		except Exception as e:
			print(f'[WAF] Error: {e}')
			return None


async def _query_balance_impl(name: str, headers: dict, cookies: dict) -> dict:
	"""余额查询的公共实现（cookie 与 access_token 两方式只差 headers/cookies 的构造）"""
	url = _api_url(ANYROUTER_CONFIG['user_info_path'])
	max_retries = 3

	for attempt in range(max_retries):
		try:
			resp = await anyrouter_request('GET', url, headers, cookies=cookies)
			blocked = anyrouter_block_reason(resp)
			if blocked:
				kind, why = blocked
				return {'name': name, 'success': False, 'error': why, 'blocked': kind}
			data = resp.json()
			if data.get('success'):
				user_data = data.get('data', {})
				return {
					'name': name,
					'success': True,
					'quota': round(user_data.get('quota', 0) / 500000, 2),
					'used': round(user_data.get('used_quota', 0) / 500000, 2),
					'username': user_data.get('username', ''),
				}
			return {
				'name': name,
				'success': False,
				'error': f'API 返回失败: {data.get("message", "Unknown")}',
			}
		except Exception as e:
			if attempt < max_retries - 1:
				await asyncio.sleep(1.5 * (attempt + 1))
				continue
			return {
				'name': name,
				'success': False,
				'error': f'{type(e).__name__}: {e}'[:150] or f'{type(e).__name__}',
			}


async def query_balance(account: AccountItem, waf_cookies: dict) -> dict:
	"""查询单个账号余额（cookie 方式，anyrouter.top）"""
	config = ANYROUTER_CONFIG
	all_cookies = {**waf_cookies, **account.cookies}

	headers = {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': config['domain'],
		'Origin': config['domain'],
		config['api_user_key']: account.api_user,
	}
	return await _query_balance_impl(account.name, headers, all_cookies)


async def query_balance_with_token(account: TokenAccountItem, waf_cookies: dict) -> dict:
	"""使用 access_token 查询单个账号余额（anyrouter.top）"""
	config = ANYROUTER_CONFIG

	headers = {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': config['domain'],
		'Origin': config['domain'],
		'Authorization': f'Bearer {account.access_token}',
		config['api_user_key']: account.user_id,
	}
	return await _query_balance_impl(account.name, headers, waf_cookies)


async def _sign_in_impl(name: str, headers: dict, cookies: dict) -> dict:
	"""签到的公共实现（cookie 与 access_token 两方式只差 headers/cookies 的构造）"""
	url = _api_url(ANYROUTER_CONFIG['sign_in_path'])
	max_retries = 3

	for attempt in range(max_retries):
		try:
			resp = await anyrouter_request('POST', url, headers, cookies=cookies)
			blocked = anyrouter_block_reason(resp)
			if blocked:
				kind, why = blocked
				return {'name': name, 'success': False, 'message': why, 'blocked': kind}
			data = resp.json()
			if data.get('success'):
				msg = data.get('message', '')
				# 空消息表示签到成功，有消息可能是"今日已签到"等
				return {
					'name': name,
					'success': True,
					'message': msg if msg else '签到成功 +$25',
					'already_signed': bool(msg),
				}
			return {'name': name, 'success': False, 'message': data.get('message', '签到失败')}
		except Exception as e:
			if attempt < max_retries - 1:
				await asyncio.sleep(1.5 * (attempt + 1))
				continue
			return {'name': name, 'success': False, 'message': f'{type(e).__name__}: {e}'[:100]}


async def sign_in(account: AccountItem, waf_cookies: dict) -> dict:
	"""为单个账号执行签到（cookie 方式，anyrouter.top）"""
	config = ANYROUTER_CONFIG
	all_cookies = {**waf_cookies, **account.cookies}

	headers = {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': f'{config["domain"]}/console',
		'Origin': config['domain'],
		config['api_user_key']: account.api_user,
		'Cache-Control': 'no-store',
	}
	return await _sign_in_impl(account.name, headers, all_cookies)


async def sign_in_with_token(account: TokenAccountItem, waf_cookies: dict) -> dict:
	"""使用 access_token 为单个账号执行签到（anyrouter.top）"""
	config = ANYROUTER_CONFIG

	headers = {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': f'{config["domain"]}/console',
		'Origin': config['domain'],
		'Authorization': f'Bearer {account.access_token}',
		config['api_user_key']: account.user_id,
		'Cache-Control': 'no-store',
	}
	return await _sign_in_impl(account.name, headers, waf_cookies)


def load_token_accounts() -> list[TokenAccountItem]:
	"""从 new_accounts_config.json 加载 access_token 账号列表"""
	return _read_json_models(NEW_ACCOUNTS_FILE, TokenAccountItem, 'TOKEN')


def agentrouter_block_reason(resp) -> str | None:
	"""认出 agentrouter 的拦截页，返回人话原因；正常返回 None。

	agentrouter 也在阿里云 WAF 后面。它的拦截页与 anyrouter 的不同：**不是那种可以用
	`_solve_acw_sc_v2()` 算出 cookie 的 `arg1` 挑战，而是滑块验证码页**（正文含
	`aliyun_waf_aa` / `slide` / `captcha`），HTTP 仍是 200，直接 `resp.json()` 会抛
	JSONDecodeError —— 看起来像代码坏了，其实是出口 IP 被 WAF 盯上了。
	程序解不了滑块，唯一的办法是停手等它过去，所以这里只负责把原因说清楚。
	"""
	try:
		body = resp.text or ''
	except Exception:
		return None
	if resp.status_code == 429:
		return '被站点限流（429），请等几分钟再试'
	if 'aliyun_waf' in body or ('slide' in body and 'captcha' in body):
		return '被阿里云 WAF 拦截（滑块验证），出口 IP 请求过多，需等一段时间自行恢复'
	return None


async def agentrouter_real_balance(cookies: dict, user_id: str) -> tuple[dict | None, str | None]:
	"""登录之后再读一次 `/api/user/self` 取真实余额，返回 (余额, 失败原因)。

	**登录响应体里的 `quota`/`used_quota` 不能用** —— 字段在，但实测恒为 0
	（2026-08-17 用 4 个账号验证：登录响应都是 $0，`/api/user/self` 是 $1725~$2415）。
	照着登录响应记账，agentrouter 的余额与用量就会全部变成 0 —— 90 天历史里一次非零都没有，
	就是这么来的。
	"""
	if not user_id:
		return None, '没有 user id'
	config = AGENTROUTER_ORG_CONFIG
	proxies = {'https': _AGENTROUTER_PROXY}

	def _do():
		sess = _get_cffi_session(_ar_session_key('agentrouter-self'), proxies)
		return sess.get(
			f'{config["domain"]}{config["user_info_path"]}',
			headers={'User-Agent': USER_AGENT, 'Accept': 'application/json', 'new-api-user': str(user_id)},
			cookies=cookies,
			timeout=15,
		)

	try:
		loop = asyncio.get_running_loop()
		resp = await loop.run_in_executor(_UPSTREAM_POOL, _do)
		blocked = agentrouter_block_reason(resp)
		if blocked:
			return None, blocked
		if resp.status_code != 200:
			return None, f'HTTP {resp.status_code}'
		try:
			data = resp.json()
		except Exception:
			return None, '响应不是 JSON（可能被拦截）'
		if not data.get('success'):
			return None, data.get('message') or 'Unknown'
		d = data.get('data') or {}
		return {
			'quota': round((d.get('quota') or 0) / 500000, 2),
			'used': round((d.get('used_quota') or 0) / 500000, 2),
			'username': d.get('username', ''),
		}, None
	except Exception as e:
		reason = f'{type(e).__name__}: {e}'[:120]
		print(f'[AGENTROUTER] 读取真实余额失败: {reason}')
		return None, reason


async def query_balance_login(account: LoginAccountItem) -> dict:
	"""通过账号密码登录查询 agentrouter.org 余额（走代理绕过 WAF）"""
	config = AGENTROUTER_ORG_CONFIG
	login_url = f"{config['domain']}{config['login_path']}"
	body = {'username': account.username, 'password': account.password}
	proxies = {'https': _AGENTROUTER_PROXY}
	max_retries = 3

	def _do():
		# key 必须带出口代数：出口轮换后复用旧代数的 Session 会继续从旧 IP 出去，
		# 与 _ar_session_key 注释里描述的轮换机制直接矛盾（其余 agentrouter 调用点都带了）
		sess = _get_cffi_session(_ar_session_key('agentrouter'), proxies)
		resp = sess.post(login_url, json=body, timeout=15)
		return resp, dict(sess.cookies)

	for attempt in range(max_retries):
		try:
			loop = asyncio.get_running_loop()
			resp, jar = await loop.run_in_executor(_UPSTREAM_POOL, _do)
			# 429 的响应体是空的，先认出来，否则 resp.json() 抛的 JSONDecodeError 完全看不出是限流
			if resp.status_code == 429:
				return {'name': account.name, 'success': False, 'error': '登录被站点限流（429），请等几分钟再试'}
			if resp.status_code == 200:
				data = resp.json()
				if data.get('success'):
					user_data = data.get('data', {})
					# 余额只认 /api/user/self，登录响应里的 quota 恒为 0（见 agentrouter_real_balance）
					real, why = await agentrouter_real_balance(jar, str(user_data.get('id') or ''))
					if real is None:
						return {
							'name': account.name,
							'success': False,
							'error': f'读取余额失败：{why}',
						}
					return {
						'name': account.name,
						'success': True,
						'quota': real['quota'],
						'used': real['used'],
						'username': real['username'] or user_data.get('username', ''),
					}
				return {
					'name': account.name,
					'success': False,
					'error': f"登录失败: {data.get('message', 'Unknown')}",
				}
			return {
				'name': account.name,
				'success': False,
				'error': f'HTTP {resp.status_code}',
			}
		except Exception as e:
			if attempt < max_retries - 1:
				await asyncio.sleep(1.5 * (attempt + 1))
				continue
			return {
				'name': account.name,
				'success': False,
				'error': f'{type(e).__name__}: {e}'[:150] or f'{type(e).__name__}',
			}


async def sign_in_login(account: LoginAccountItem) -> dict:
	"""通过账号密码登录自动签到（agentrouter.org 登录即签到）"""
	config = AGENTROUTER_ORG_CONFIG
	login_url = f"{config['domain']}{config['login_path']}"
	body = {'username': account.username, 'password': account.password}
	proxies = {'https': _AGENTROUTER_PROXY}
	max_retries = 3

	def _do():
		# 连接池 key 必须带出口代数：mihomo 切节点不杀旧隧道，复用旧 Session 会继续从旧出口出去
		sess = _get_cffi_session(_ar_session_key('agentrouter'), proxies)
		resp = sess.post(login_url, json=body, timeout=15)
		return resp, dict(sess.cookies)

	for attempt in range(max_retries):
		try:
			loop = asyncio.get_running_loop()
			resp, jar = await loop.run_in_executor(_UPSTREAM_POOL, _do)
			if resp.status_code == 429:
				return {'name': account.name, 'success': False, 'message': '登录被站点限流（429），请等几分钟再试'}
			blocked = agentrouter_block_reason(resp)
			if blocked:
				# 滑块页是 200 + HTML，不先认出来 resp.json() 会抛 JSONDecodeError，看不出是被拦
				return {'name': account.name, 'success': False, 'message': f'登录被拦: {blocked}'}
			if resp.status_code != 200:
				return {'name': account.name, 'success': False, 'message': f'登录失败: HTTP {resp.status_code}'}
			login_data = resp.json()
			if not login_data.get('success'):
				return {
					'name': account.name,
					'success': False,
					'message': f"登录失败: {login_data.get('message', 'Unknown')}",
				}
			user_data = login_data.get('data', {})
			checked_in = user_data.get('checked_in', False)
			# checked_in 取自登录响应（这个字段是准的）；余额必须另取，
			# 登录响应里的 quota 恒为 0（见 agentrouter_real_balance）。
			# 取不到就把 quota 留成 None —— 调用方据此跳过记账，
			# 免得把 0 写进今日基线，那会让这个账号当天的用量永远算不出来。
			real, why = await agentrouter_real_balance(jar, str(user_data.get('id') or ''))
			if real is None:
				add_checkin_log(f'{account.name}: 签到成功但读取余额失败（{why}），本次不记用量')
			return {
				'name': account.name,
				'success': True,
				'message': '今日已签到' if checked_in else '签到成功',
				'already_signed': checked_in,
				'quota': real['quota'] if real else None,
				'used': real['used'] if real else None,
			}
		except Exception as e:
			if attempt < max_retries - 1:
				await asyncio.sleep(1.5 * (attempt + 1))
				continue
			return {'name': account.name, 'success': False, 'message': f'{type(e).__name__}: {e}'[:100]}



def load_login_accounts() -> list[LoginAccountItem]:
	"""从 agentrouter_accounts.json 加载登录方式账号列表"""
	return _read_json_models(AGENTROUTER_ACCOUNTS_FILE, LoginAccountItem, 'LOGIN')


# ========== 通用 new-api 站点（access_token 方式）==========
# 这一段是站点无关的：所有函数都以 NewapiSite 为第一个参数，站点清单来自 newapi_sites.json。
# 加一个新站点不需要改这里的任何代码，只要在前端「站点管理」里填域名即可。


def load_newapi_sites() -> list[NewapiSite]:
	"""读取 newapi_sites.json；文件不存在时用 NEWAPI_SEED_SITES 初始化后再读。"""
	if not NEWAPI_SITES_FILE.exists():
		try:
			_atomic_write_json(NEWAPI_SITES_FILE, NEWAPI_SEED_SITES, indent=2)
			print(f'[SITE] 已初始化 newapi_sites.json（{len(NEWAPI_SEED_SITES)} 个站点）')
		except Exception as e:
			print(f'[SITE] 初始化 newapi_sites.json 失败: {e}')
			return [NewapiSite(**s) for s in NEWAPI_SEED_SITES]
	return _read_json_models(NEWAPI_SITES_FILE, NewapiSite, 'SITE')


def save_newapi_sites(sites: list[NewapiSite]):
	"""写回站点清单"""
	_atomic_write_json(NEWAPI_SITES_FILE, [s.model_dump() for s in sites], indent=2)


def get_newapi_site(site_id: str) -> NewapiSite | None:
	"""按 id 取站点配置，找不到返回 None"""
	for s in load_newapi_sites():
		if s.id == site_id:
			return s
	return None


# ========== 站点健康自动巡检 ==========
# 站点三态状态平时只在查询/签到时更新，死了的站点会一直挂在注册表里每天空跑
# （实测出现过 521/522/404 的死站）。巡检调度器低频 GET /api/status（不挂中间件、
# 1 站点 1 请求），连续 SITE_PATROL_FAIL_LIMIT 次不可达就自动暂停该站点的每日签到
# 并推 webhook；恢复可达只更新状态，重新开启签到留给用户决定（站点可能换域名复活）。
SITE_PATROL_INTERVAL = 6 * 3600  # 巡检间隔 6 小时
SITE_PATROL_FIRST_DELAY = 300  # 启动 5 分钟后首巡（避开启动高峰）
SITE_PATROL_FAIL_LIMIT = 3
site_patrol_fails: dict[str, int] = {}


async def run_site_patrol() -> None:
	"""巡检一轮全部站点，更新三态状态并在持续失联时自动暂停签到"""
	sites = load_newapi_sites()
	if not sites:
		return
	for s in sites:
		try:
			resp = await newapi_request(s, 'GET', s.status_path, {'User-Agent': USER_AGENT})
			ok = resp.status_code == 200
			if ok:
				try:
					ok = bool((resp.json() or {}).get('data', {}).get('version'))
				except Exception:
					ok = False
		except Exception:
			ok = False

		if ok:
			if site_patrol_fails.get(s.id, 0) >= SITE_PATROL_FAIL_LIMIT:
				add_newapi_checkin_log(s, '巡检：站点恢复可达（每日签到仍为暂停，请手动重新开启）')
			site_patrol_fails[s.id] = 0
			if _site_status.get(s.id, {}).get('status') == 'invalid':
				_set_site_status(s.id, 'unknown', '')
			continue

		n = site_patrol_fails.get(s.id, 0) + 1
		site_patrol_fails[s.id] = n
		if n >= SITE_PATROL_FAIL_LIMIT and s.auto_checkin:
			current = load_newapi_sites()
			for s2 in current:
				if s2.id == s.id:
					s2.auto_checkin = False
			save_newapi_sites(current)
			msg = f'巡检：连续 {n} 次不可达，已自动暂停每日签到'
			add_newapi_checkin_log(s, msg)
			_set_site_status(s.id, 'invalid', f'巡检连续 {n} 次不可达')
			if notify_configured():
				_spawn(send_webhook_notify(
					f'⚠️ {s.label} 已失联',
					f'{s.domain} 连续 {n} 次巡检不可达，已自动暂停每日签到。\n站点恢复后请在站点管理重新开启自动签到。',
				))


async def site_patrol_scheduler():
	"""低频巡检调度器：先等首巡延迟，然后每 6 小时一轮"""
	await asyncio.sleep(SITE_PATROL_FIRST_DELAY)
	while True:
		try:
			await run_site_patrol()
		except Exception as e:
			print(f'[PATROL] 巡检异常: {e}')
		await asyncio.sleep(SITE_PATROL_INTERVAL)


def load_newapi_accounts(site: NewapiSite) -> list[NewapiAccountItem]:
	"""从站点自己的 accounts_file 加载账号列表"""
	return _read_json_models(site.accounts_path(), NewapiAccountItem, site.id.upper())


def save_newapi_accounts(site: NewapiSite, accounts: list[NewapiAccountItem]):
	"""保存账号列表到站点自己的 accounts_file"""
	_atomic_write_json(site.accounts_path(), [a.model_dump() for a in accounts], indent=2)


def _newapi_headers(site: NewapiSite, account: NewapiAccountItem) -> dict:
	"""new-api 请求头：Bearer token + New-Api-User，两者缺一即 401"""
	return {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': f'{site.domain}/console',
		'Origin': site.domain,
		'Authorization': f'Bearer {account.access_token}',
		site.api_user_key: account.user_id,
		'Cache-Control': 'no-store',
	}


async def newapi_request(site: NewapiSite, method: str, path: str, headers: dict, json_body=None, _auto_bypass: bool = True):
	"""向 new-api 站点发请求。这类站点在 Cloudflare 后，实测无需代理/WAF cookie，仍带 Chrome 指纹更稳。

	Session 按站点分开复用（key 用 site.id），避免不同域名共用连接池。

	撞上 CF 边缘质询或阿里云 WAF 挑战页时，解一次防护 cookies（按域名缓存 5 分钟）后
	原地重打一次；有缓存就直接带上。cf_clearance 绑 UA，重试时用求解方返回的同一个 UA。
	挑战页由防护层返回，请求没到过 new-api 源站，重试对签到是安全的（不会重复签）。
	"""
	url = site.domain + path
	prot = protection_cache.get(site.domain.rstrip('/'))
	if prot and (prot.get('failed') or prot['expires'] <= time.time()):
		prot = None  # 负缓存/过期条目对请求方不可见；负缓存的拦截图在 ensure 里做
	send_headers = dict(headers)
	if prot and prot.get('user_agent'):
		send_headers['User-Agent'] = prot['user_agent']

	def _do():
		sess = _get_cffi_session(f'newapi:{site.id}')
		if prot:
			sess.cookies.update(prot['cookies'])
		return sess.request(method.upper(), url, headers=send_headers, json=json_body)

	loop = asyncio.get_running_loop()
	resp = await loop.run_in_executor(_UPSTREAM_POOL, _do)
	if not _auto_bypass:
		return resp
	kind = detect_protection(resp)
	if kind is None:
		return resp
	if prot:
		# 带着缓存的 cookies 仍撞质询：这条缓存已坏（被吊销/过期），作废后强制重解，
		# 否则 ensure 会命中同一条「新鲜但无效」的缓存，拿同样的坏 cookies 白打一次
		protection_cache.pop(site.domain.rstrip('/'), None)
	entry = await ensure_protection_cookies(site, kind)
	if not entry:
		print(f'[{site.id.upper()}] 撞上 {kind} 防护但未能过验（CF 质询需在设置页配置 FlareSolverr）')
		return resp
	print(f'[{site.id.upper()}] 撞上 {kind} 防护，已过验并自动重试')
	return await newapi_request(site, method, path, headers, json_body, _auto_bypass=False)


async def _proxied_newapi_request(site: NewapiSite, method: str, path: str, headers: dict, json_body=None):
	"""经本地 mihomo 出口向站点发一次性请求（不复用 Session 池）。

	newapi_request 是直连的（这类站点平时不需要代理）；只有撞「按出口 IP 限流」的端点
	（取全量 key 的 batch/keys，20 次/20 分钟/IP）才借 mihomo 换出口。这里每次都新建连接，
	不存在 keep-alive 隧道钉死旧出口的问题（agentrouter 轮换踩过的坑）。
	"""
	from curl_cffi import requests as cffi_requests

	url = site.domain + path
	proxies = {'https': _LOCAL_PROXY, 'http': _LOCAL_PROXY}

	def _do():
		return cffi_requests.request(
			method.upper(), url, headers=headers, json=json_body,
			proxies=proxies, impersonate='chrome131', timeout=20,
		)

	loop = asyncio.get_running_loop()
	return await loop.run_in_executor(_UPSTREAM_POOL, _do)


async def query_balance_newapi(site: NewapiSite, account: NewapiAccountItem) -> dict:
	"""查询单个账号余额（access_token 方式）"""
	headers = _newapi_headers(site, account)
	unit = site.quota_per_unit or 500000
	max_retries = 3
	for attempt in range(max_retries):
		try:
			resp = await newapi_request(site, 'GET', site.user_info_path, headers)
			if resp.status_code == 200:
				data = resp.json()
				if data.get('success'):
					user_data = data.get('data', {})
					return {
						'name': account.name,
						'success': True,
						'quota': round(user_data.get('quota', 0) / unit, 2),
						'used': round(user_data.get('used_quota', 0) / unit, 2),
						'username': user_data.get('username', ''),
					}
				return {'name': account.name, 'success': False, 'error': f'API 返回失败: {data.get("message", "Unknown")}'}
			return {'name': account.name, 'success': False, 'error': f'HTTP {resp.status_code}'}
		except Exception as e:
			if attempt < max_retries - 1:
				await asyncio.sleep(1.5 * (attempt + 1))
				continue
			return {'name': account.name, 'success': False, 'error': f'{type(e).__name__}: {e}'[:150]}


async def newapi_turnstile_status(site: NewapiSite) -> dict:
	"""探测站点当前是否开着 Turnstile 人机校验，带 5 分钟缓存。

	`GET /api/status` 会返回 `data.turnstile_check` 与 `data.turnstile_site_key`。
	站长若哪天关掉 Turnstile，这里会自动变成 enabled=False，服务器端签到随即恢复可用，
	前端也就不再需要走「浏览器脚本 + 同步」那条路 —— 无需改代码。

	sitekey 一律从这里读，不要硬编码：它有域名限制，各站点各不相同。
	探测失败时保守假定 enabled=True（宁可提示用户手动签，也别让自动签到静默失败）。
	"""
	cache_key = f'turnstile:{site.id}'
	cached = waf_cache.get(cache_key)
	if cached and cached['expires'] > time.time():
		return cached['value']

	value = {'enabled': True, 'site_key': '', 'probed': False}
	try:
		resp = await newapi_request(site, 'GET', site.status_path, {'User-Agent': USER_AGENT})
		if resp.status_code == 200:
			data = (resp.json() or {}).get('data', {}) or {}
			value = {
				'enabled': bool(data.get('turnstile_check')),
				'site_key': data.get('turnstile_site_key') or '',
				'probed': True,
			}
	except Exception as e:
		print(f'[{site.id.upper()}] Turnstile 状态探测失败，保守假定已开启: {e}')

	waf_cache[cache_key] = {'value': value, 'expires': time.time() + WAF_CACHE_TTL}
	return value


# ========== Turnstile 打码平台（服务器端过 CF 人机校验）==========
# 站点开着 Turnstile 时，签到 POST 必须带一次性 token。浏览器场景由前端生成的 Console
# 脚本现场渲染 widget 取 token；服务器侧则接打码平台代解。三家主流平台（2Captcha /
# YesCaptcha / CapSolver）都兼容 createTask + getTaskResult 协议，差异只有域名和 task.type。
TURNSTILE_SOLVER_PRESETS = {
	'2captcha': {'base_url': 'https://api.2captcha.com', 'task_type': 'TurnstileTaskProxyless'},
	'yescaptcha': {'base_url': 'https://api.yescaptcha.com', 'task_type': 'TurnstileTaskProxyless'},
	'capsolver': {'base_url': 'https://api.capsolver.com', 'task_type': 'AntiTurnstileTaskProxyLess'},
}
# 打码按次计费且平台侧有限速，求解并发固定 3，不跟站点签到并发（10）走
_TURNSTILE_SOLVER_SEM = asyncio.Semaphore(3)
TURNSTILE_SOLVER_POLL_INTERVAL = 3  # 秒
TURNSTILE_SOLVER_TIMEOUT = 150  # 单个 token 求解上限


def get_turnstile_solver_config() -> dict:
	"""读打码平台配置（saved_config.json 的 turnstile_solver 段），缺省即未配置。"""
	try:
		cfg = _read_json_cached(CONFIG_FILE)
	except Exception:
		cfg = {}
	s = cfg.get('turnstile_solver') if isinstance(cfg, dict) else None
	s = s if isinstance(s, dict) else {}
	provider = (s.get('provider') or '').strip().lower()
	api_key = (s.get('api_key') or '').strip()
	base_url = (s.get('base_url') or '').strip().rstrip('/')
	preset = TURNSTILE_SOLVER_PRESETS.get(provider)
	return {
		'provider': provider,
		'api_key': api_key,
		'base_url': base_url or (preset['base_url'] if preset else ''),
		# 自定义网关没指 task.type 时按 2Captcha 协议猜——绝大多数兼容网关都认这个名字
		'task_type': preset['task_type'] if preset else ('TurnstileTaskProxyless' if base_url else ''),
	}


async def solve_turnstile_token(site_key: str, page_url: str, timeout: int = TURNSTILE_SOLVER_TIMEOUT) -> dict:
	"""调打码平台解一个 Turnstile token，成功返回 {'success': True, 'token': ...}。

	对外入口：先做不触网的预检（未配置/缺 sitekey 不计费用统计），再交给 _raw 实际
	求解并按结果更新当日用量计数（solved / failed，落盘跨重启）。
	"""
	cfg = get_turnstile_solver_config()
	if not (cfg['api_key'] and cfg['base_url'] and cfg['task_type']):
		return {'success': False, 'error': '打码平台未配置（设置页选择平台并填 api_key）'}
	if not site_key:
		return {'success': False, 'error': '缺少 sitekey（站点状态探测失败）'}
	r = await _solve_turnstile_token_raw(cfg, site_key, page_url, timeout)
	_solver_stats_bump(bool(r.get('success')))
	return r


async def _solve_turnstile_token_raw(cfg: dict, site_key: str, page_url: str, timeout: int) -> dict:
	"""实际调打码平台。同一 token 只能用一次（new-api 转发给 CF siteverify 后即作废），
	每个账号签到前各解一个。CapSolver 的 createTask 可能直接带 solution.token，
	与轮询 getTaskResult 两种返回方式一并兼容。
	"""
	def _post(path: str, payload: dict):
		sess = _get_cffi_session(f'turnstile-solver:{cfg["base_url"]}')
		return sess.post(cfg['base_url'] + path, json=payload, timeout=30)

	loop = asyncio.get_running_loop()

	async with _TURNSTILE_SOLVER_SEM:
		try:
			resp = await loop.run_in_executor(_UPSTREAM_POOL, _post, '/createTask', {
				'clientKey': cfg['api_key'],
				'task': {'type': cfg['task_type'], 'websiteURL': page_url, 'websiteKey': site_key},
			})
			data = resp.json()
			if data.get('errorId'):
				return {'success': False, 'error': f"createTask 失败: {data.get('errorCode') or data.get('errorDescription')}"}
			token = (data.get('solution') or {}).get('token')
			if token:
				return {'success': True, 'token': token}
			task_id = data.get('taskId')
			if not task_id:
				return {'success': False, 'error': f'createTask 响应异常: {str(data)[:150]}'}

			deadline = time.monotonic() + timeout
			while time.monotonic() < deadline:
				await asyncio.sleep(TURNSTILE_SOLVER_POLL_INTERVAL)
				resp = await loop.run_in_executor(_UPSTREAM_POOL, _post, '/getTaskResult', {
					'clientKey': cfg['api_key'], 'taskId': task_id,
				})
				data = resp.json()
				if data.get('errorId'):
					return {'success': False, 'error': f"求解失败: {data.get('errorCode') or data.get('errorDescription')}"}
				if data.get('status') == 'ready':
					token = (data.get('solution') or {}).get('token')
					if token:
						return {'success': True, 'token': token}
					return {'success': False, 'error': '平台返回 ready 但没有 token'}
			return {'success': False, 'error': f'求解超时（{timeout}s 未就绪）'}
		except Exception as e:
			return {'success': False, 'error': f'{type(e).__name__}: {e}'[:150]}


# ========== 通用站点防护层（CF 边缘质询 / 阿里云 WAF）==========
# new-api 站点常见的网络层防护有两类：Cloudflare 边缘质询（cf-mitigated: challenge，
# 403/503 +「Just a moment」页）和阿里云 WAF 的 acw_sc__v2 挑战（正文 var arg1='...'）。
# 后者是纯算法可直接解；前者无浏览器解不了，借自托管开源项目 FlareSolverr 代过——
# cf_clearance 与出口 IP、User-Agent 双重绑定，FlareSolverr 必须与本服务同出口。
# newapi_request 撞到防护时自动取 cookies 原地重打一次：挑战页由防护层返回，请求没到过
# new-api 源站，重试对签到是安全的（不会重复签）。

_CF_CHALLENGE_BODY_RE = re.compile(r'Just a moment|challenge-platform|_cf_chl|cf-chl|Checking your browser', re.I)
_ALIYUN_WAF_COOKIE_NAMES = ('acw_tc', 'cdn_sec_tc', 'acw_sc__v2')

# 防护 cookies 缓存：{domain: {'cookies': dict, 'user_agent': str|None, 'expires': float}}，TTL 沿用 WAF_CACHE_TTL
protection_cache: dict = {}
_protection_locks: dict[str, asyncio.Lock] = {}


def get_flaresolverr_url() -> str:
	"""FlareSolverr 地址（saved_config.json 的 turnstile_solver.flaresolverr_url），未配置返回空串。"""
	try:
		cfg = _read_json_cached(CONFIG_FILE)
	except Exception:
		cfg = {}
	s = cfg.get('turnstile_solver') if isinstance(cfg, dict) else None
	return ((s or {}).get('flaresolverr_url') or '').strip().rstrip('/')


def detect_protection(resp) -> str | None:
	"""识别响应背后的防护层：'cf_challenge' / 'aliyun_waf'；正常返回 None。

	CF 以官方 cf-mitigated 响应头为准，正文特征兜底（质询页变体多，头最可靠）；
	阿里云 WAF 挑战页在 200 里也可能出现（校验中转页），认 arg1 特征。
	"""
	try:
		headers = resp.headers or {}
		body = resp.text or ''
	except Exception:
		return None
	if str(headers.get('cf-mitigated', '')).lower() == 'challenge':
		return 'cf_challenge'
	if resp.status_code in (403, 503) and _CF_CHALLENGE_BODY_RE.search(body):
		return 'cf_challenge'
	if _WAF_CHALLENGE_RE.search(body):
		return 'aliyun_waf'
	return None


async def solve_aliyun_waf(domain: str) -> dict | None:
	"""过任意域名的阿里云 WAF 挑战：GET 首页 → 提 arg1 → 算 acw_sc__v2。失败返回 None。

	独立 Session 收挑战页下发的 acw_tc/cdn_sec_tc（acw_sc__v2 与它们配对校验），
	直连不走代理——这类站点平时不需要代理。
	"""
	def _do():
		from curl_cffi import requests as cffi_requests

		sess = cffi_requests.Session(impersonate='chrome131', timeout=30)
		resp = sess.get(domain + '/', headers={'User-Agent': USER_AGENT})
		m = _WAF_CHALLENGE_RE.search(resp.text or '')
		if not m:
			return None
		cookies = {}
		for name in _ALIYUN_WAF_COOKIE_NAMES:
			val = sess.cookies.get(name)
			if val:
				cookies[name] = val
		cookies['acw_sc__v2'] = _solve_acw_sc_v2(m.group(1))
		return {'cookies': cookies, 'user_agent': None}

	loop = asyncio.get_running_loop()
	try:
		return await loop.run_in_executor(_UPSTREAM_POOL, _do)
	except Exception as e:
		print(f'[PROTECT] {domain} 阿里云 WAF 求解失败: {e}')
		return None


async def solve_cf_challenge(domain: str) -> dict | None:
	"""用 FlareSolverr 过 Cloudflare 边缘质询，返回 {cookies, user_agent}。

	未配置 FlareSolverr 时直接返回 None——保持旧行为：撞质询就让调用方拿到 403/503。
	"""
	base = get_flaresolverr_url()
	if not base:
		return None

	def _do():
		sess = _get_cffi_session(f'flaresolverr:{base}')
		return sess.post(base + '/v1', json={'cmd': 'request.get', 'url': domain + '/', 'maxTimeout': 60000}, timeout=70)

	loop = asyncio.get_running_loop()
	try:
		resp = await loop.run_in_executor(_UPSTREAM_POOL, _do)
		data = resp.json()
		if data.get('status') != 'ok':
			print(f'[PROTECT] {domain} FlareSolverr 求解失败: {str(data.get("message"))[:120]}')
			return None
		solution = data.get('solution') or {}
		cookies = {c.get('name'): c.get('value') for c in solution.get('cookies', []) if c.get('name')}
		if not cookies:
			return None
		return {'cookies': cookies, 'user_agent': solution.get('userAgent') or None}
	except Exception as e:
		print(f'[PROTECT] {domain} FlareSolverr 调用失败: {e}')
		return None


async def ensure_protection_cookies(site: NewapiSite, kind: str) -> dict | None:
	"""确保某站点的防护 cookies 就绪（成功缓存 5 分钟，失败负缓存 60 秒），失败返回 None。

	singleflight 很重要：签到是 10 并发，缓存过期瞬间不能让每个账号各打一次
	FlareSolverr/WAF 挑战页（前者按次耗时几十秒，后者可能撞 IP 限流）。
	失败也记一段短负缓存：FlareSolverr 挂掉时一批 10 个账号不至各自等满 70 秒超时，
	60 秒后自动允许重试，不影响「服务恢复即恢复签到」。
	"""
	domain = site.domain.rstrip('/')
	cached = protection_cache.get(domain)
	if cached and cached.get('failed'):
		# 负缓存：近期刚失败过，别再去撞求解器
		if cached['expires'] > time.time():
			return None
		protection_cache.pop(domain, None)
		cached = None
	if cached and cached['expires'] > time.time():
		return cached
	lock = _protection_locks.setdefault(domain, asyncio.Lock())
	async with lock:
		cached = protection_cache.get(domain)
		if cached and cached.get('failed') and cached['expires'] > time.time():
			return None
		if cached and not cached.get('failed') and cached['expires'] > time.time():
			return cached
		if kind == 'aliyun_waf':
			solved = await solve_aliyun_waf(domain)
		elif kind == 'cf_challenge':
			solved = await solve_cf_challenge(domain)
		else:
			solved = None
		if not solved:
			protection_cache[domain] = {'failed': True, 'expires': time.time() + 60}
			return None
		entry = {**solved, 'expires': time.time() + WAF_CACHE_TTL}
		protection_cache[domain] = entry
		return entry


async def probe_page_protection(domain: str) -> dict:
	"""裸探测站点首页的防护层（不走 newapi_request 的自动过验），供添加站点时分类展示。"""
	def _do():
		from curl_cffi import requests as cffi_requests

		sess = cffi_requests.Session(impersonate='chrome131', timeout=30)
		return sess.get(domain + '/', headers={'User-Agent': USER_AGENT})

	loop = asyncio.get_running_loop()
	try:
		resp = await loop.run_in_executor(_UPSTREAM_POOL, _do)
		kind = detect_protection(resp)
		return {
			'http_status': resp.status_code,
			'cf_challenge': kind == 'cf_challenge',
			'aliyun_waf': kind == 'aliyun_waf',
		}
	except Exception as e:
		return {'http_status': None, 'cf_challenge': False, 'aliyun_waf': False, 'error': str(e)[:100]}


# ========== Webhook 通知（Telegram / Server酱 / Bark / 通用）==========
# 邮件之外的第二条告警通道。配置存 saved_config.json 的 notify 段（该文件已在
# gitignore 里且仅服务端持有，webhook URL 里的 bot token 与账号 token 同级敏感）。
# 三家的差异只在请求形状，这里抹平成统一的 (title, body) 入口。

def get_notify_config() -> dict:
	"""读通知配置；未配置时返回 on_alert=True / on_checkin_failed=False 的默认值。"""
	try:
		cfg = _read_json_cached(CONFIG_FILE)
	except Exception:
		cfg = {}
	n = cfg.get('notify') if isinstance(cfg, dict) else None
	n = n if isinstance(n, dict) else {}
	return {
		'type': (n.get('type') or '').strip().lower(),
		'url': (n.get('url') or '').strip(),
		'chat_id': (n.get('chat_id') or '').strip(),
		'on_alert': bool(n.get('on_alert', True)),
		'on_checkin_failed': bool(n.get('on_checkin_failed', False)),
	}


def notify_configured() -> bool:
	n = get_notify_config()
	return bool(n['url']) and n['type'] in ('telegram', 'serverchan', 'bark', 'generic')


async def send_webhook_notify(title: str, body: str) -> dict:
	"""按配置发一条通知，返回 {sent: bool, error?}。未配置/发送失败都不抛异常。

	Telegram 用 sendMessage（URL 含 bot token，chat_id 单独存）；Server酱是
	KEY.send 表单；Bark 是 <key>/push 的 JSON；通用网关 POST {title, message}。
	"""
	n = get_notify_config()
	if not notify_configured():
		return {'sent': False, 'error': '通知未配置'}

	# 各渠道请求形状不同：Telegram/通用收 JSON，Server酱只认表单编码，
	# Bark 官方形式是 POST {origin}/push 且 device_key 放 body
	form_data = None
	if n['type'] == 'telegram':
		url = n['url']
		payload = {'chat_id': n['chat_id'], 'text': f'{title}\n\n{body}'}
	elif n['type'] == 'serverchan':
		url = n['url'] if n['url'].endswith('.send') else n['url'].rstrip('/') + '.send'
		payload = {'title': title, 'desp': body}
		form_data = payload
	elif n['type'] == 'bark':
		parsed = urlparse(n['url'])
		device_key = parsed.path.rstrip('/').rpartition('/')[2]
		if not device_key:
			return {'sent': False, 'error': 'Bark URL 里没有 device key（应为 https://api.day.app/<key>）'}
		url = f'{parsed.scheme}://{parsed.netloc}/push'
		payload = {'device_key': device_key, 'title': title, 'body': body, 'group': 'newapi-checkin'}
	else:
		url = n['url']
		payload = {'title': title, 'message': body}

	def _do():
		sess = _get_cffi_session('notify')
		if form_data is not None:
			return sess.post(url, data=form_data, timeout=15)
		return sess.post(url, json=payload, timeout=15)

	loop = asyncio.get_running_loop()
	try:
		resp = await loop.run_in_executor(_UPSTREAM_POOL, _do)
		if resp.status_code != 200:
			return {'sent': False, 'error': f'HTTP {resp.status_code}'}
		return {'sent': True}
	except Exception as e:
		return {'sent': False, 'error': f'{type(e).__name__}: {e}'[:120]}


def _mask_secret(value: str) -> str:
	"""URL 里通常嵌着 bot token / sendkey，API 回显只露首尾（短 key 最多露 8 字符）。"""
	if len(value) <= 40:
		return value[:8] + '…' if value else ''
	return value[:28] + '…' + value[-8:]


# ── 打码用量统计：按天计数（次数 = 费用），跨重启持久化到 solver_stats.json ──
SOLVER_STATS_FILE = Path(__file__).parent / 'solver_stats.json'


def _solver_stats() -> dict:
	today = datetime.now().strftime('%Y-%m-%d')
	try:
		data = json.loads(SOLVER_STATS_FILE.read_text(encoding='utf-8'))
	except Exception:
		data = {}
	if not isinstance(data, dict) or data.get('date') != today:
		data = {'date': today, 'solved': 0, 'failed': 0}
	return data


def _solver_stats_bump(ok: bool) -> None:
	try:
		data = _solver_stats()
		data['solved' if ok else 'failed'] = data.get('solved' if ok else 'failed', 0) + 1
		_atomic_write_json(SOLVER_STATS_FILE, data)
	except Exception as e:
		print(f'[SOLVER] 用量统计写入失败: {e}')


@app.get('/api/turnstile/solver/stats')
async def solver_stats():
	"""今日打码用量（成功/失败次数，失败也消耗平台侧部分配额）"""
	return {'success': True, 'stats': _solver_stats()}


@app.post('/api/turnstile/solver/balance')
async def solver_balance():
	"""查询打码平台账户余额（按次查询，前端按钮触发，不自动轮询）。

	2Captcha 用 res.php?action=getbalance，YesCaptcha/CapSolver/自定义网关走
	createTask 同族的 POST /getBalance {clientKey}。
	"""
	cfg = get_turnstile_solver_config()
	if not cfg['api_key']:
		return {'success': False, 'error': '打码平台未配置'}

	def _do_2captcha():
		sess = _get_cffi_session(f'turnstile-solver:{cfg["base_url"]}')
		return sess.get(f'{cfg["base_url"]}/res.php', params={'key': cfg['api_key'], 'action': 'getbalance', 'json': 1}, timeout=15)

	def _do_getbalance():
		sess = _get_cffi_session(f'turnstile-solver:{cfg["base_url"]}')
		return sess.post(cfg['base_url'] + '/getBalance', json={'clientKey': cfg['api_key']}, timeout=15)

	loop = asyncio.get_running_loop()
	try:
		if cfg['provider'] == '2captcha':
			data = (await loop.run_in_executor(_UPSTREAM_POOL, _do_2captcha)).json()
			# {"status":1,"request":"9.12"} 或 {"status":0,"request":"ERROR_..."}
			if str(data.get('status')) == '1':
				return {'success': True, 'balance': float(data.get('request', 0))}
			return {'success': False, 'error': str(data.get('request'))[:100]}
		resp = await loop.run_in_executor(_UPSTREAM_POOL, _do_getbalance)
		data = resp.json()
		if data.get('errorId'):
			return {'success': False, 'error': str(data.get('errorCode') or data.get('errorDescription'))[:100]}
		if data.get('balance') is not None:
			return {'success': True, 'balance': float(data['balance'])}
		return {'success': False, 'error': f'响应异常: {str(data)[:100]}'}
	except Exception as e:
		return {'success': False, 'error': f'{type(e).__name__}: {e}'[:120]}


@app.get('/api/notify')
async def get_notify():
	"""通知配置状态，URL 打码回显"""
	n = get_notify_config()
	return {
		'success': True,
		'notify': {
			'type': n['type'],
			'chat_id': n['chat_id'],
			'url_masked': _mask_secret(n['url']) if n['url'] else '',
			'configured': notify_configured(),
			'on_alert': n['on_alert'],
			'on_checkin_failed': n['on_checkin_failed'],
		},
	}


class NotifyRequest(BaseModel):
	"""通知配置。url 留空表示保留已保存的值（URL 含 token，不回显也就无法重传）。"""

	type: str
	url: str = ''
	chat_id: str = ''
	on_alert: bool = True
	on_checkin_failed: bool = False


@app.post('/api/notify')
async def save_notify(req: NotifyRequest):
	"""保存通知配置（合并写 saved_config.json，不动其他段）"""
	ntype = req.type.strip().lower()
	if ntype not in ('telegram', 'serverchan', 'bark', 'generic'):
		return {'success': False, 'error': f'未知通知类型: {req.type}（可选 telegram / serverchan / bark / generic）'}
	try:
		data = dict(_read_json_cached(CONFIG_FILE) or {}) if CONFIG_FILE.exists() else {}
	except Exception:
		data = {}
	saved = data.get('notify') or {}
	# 换渠道必须重填 URL：不同渠道的 URL 格式互不兼容（Telegram 带路径 token、
	# Server酱是 KEY.send、Bark 是 device key），沿用旧 URL 只会得到必然失败的配置
	if not req.url.strip() and saved.get('url') and (saved.get('type') or ntype) != ntype:
		return {'success': False, 'error': f'从 {saved.get("type")} 切换到 {ntype} 需要重新填写新渠道的 URL'}
	data['notify'] = {
		'type': ntype,
		'url': req.url.strip() or saved.get('url') or '',
		'chat_id': req.chat_id.strip(),
		'on_alert': req.on_alert,
		'on_checkin_failed': req.on_checkin_failed,
	}
	_atomic_write_json(CONFIG_FILE, data, indent=2)
	return {'success': True, 'message': '通知配置已保存'}


@app.post('/api/notify/test')
async def test_notify():
	"""发一条测试通知验证配置"""
	if not notify_configured():
		return {'success': False, 'error': '请先保存完整配置（类型 + URL）'}
	r = await send_webhook_notify('✅ 测试通知', 'newapi-checkin 通知通道配置成功，这是一条测试消息。')
	if r['sent']:
		return {'success': True, 'message': '测试通知已发送'}
	return {'success': False, 'error': r.get('error', '发送失败')}


async def sign_in_newapi(site: NewapiSite, account: NewapiAccountItem, turnstile_token: str | None = None) -> dict:
	"""为单个账号签到（POST /api/user/checkin，奖励区间由站点配置决定）。

	今日已签时接口返回 200 且 success=false、message='今日已签到'，据此区分 already。

	turnstile_token 传入时签到 URL 带上 ?turnstile=<token> —— new-api 的 TurnstileCheck
	中间件只认 query 参数，与前端浏览器脚本的传法一致。

	站点开着 Turnstile 且没传 token 时，接口会返回「Turnstile token 为空」——
	此时把 `turnstile_blocked` 标出来，让调用方知道这不是账号问题，而是需要先过人机校验。
	"""
	headers = _newapi_headers(site, account)
	path = site.sign_in_path + (f'?turnstile={quote(turnstile_token, safe="")}' if turnstile_token else '')
	max_retries = 3
	for attempt in range(max_retries):
		try:
			resp = await newapi_request(site, 'POST', path, headers)
			if resp.status_code == 200:
				data = resp.json()
				msg = data.get('message', '')
				if data.get('success'):
					return {'name': account.name, 'success': True, 'message': msg or '签到成功', 'already_signed': False}
				if '已签' in msg:
					return {'name': account.name, 'success': True, 'message': msg, 'already_signed': True}
				if 'Turnstile' in msg:
					return {'name': account.name, 'success': False, 'message': msg, 'turnstile_blocked': True}
				return {'name': account.name, 'success': False, 'message': msg or '签到失败'}
			return {'name': account.name, 'success': False, 'message': f'HTTP {resp.status_code}'}
		except Exception as e:
			if attempt < max_retries - 1:
				await asyncio.sleep(1.5 * (attempt + 1))
				continue
			return {'name': account.name, 'success': False, 'message': f'{type(e).__name__}: {e}'[:100]}


async def newapi_checkin_info(site: NewapiSite, account: NewapiAccountItem) -> dict:
	"""读取单个账号的签到状态（GET /api/user/checkin），不触发签到"""
	unit = site.quota_per_unit or 500000
	try:
		resp = await newapi_request(site, 'GET', site.sign_in_path, _newapi_headers(site, account))
		if resp.status_code != 200:
			return {'name': account.name, 'success': False, 'error': f'HTTP {resp.status_code}'}
		data = resp.json()
		if not data.get('success'):
			return {'name': account.name, 'success': False, 'error': data.get('message', 'Unknown')}
		d = data.get('data', {})
		stats = d.get('stats', {}) or {}
		return {
			'name': account.name,
			'success': True,
			'enabled': d.get('enabled'),
			'min_reward': round((d.get('min_quota') or 0) / unit, 2),
			'max_reward': round((d.get('max_quota') or 0) / unit, 2),
			'checked_in_today': stats.get('checked_in_today'),
			'total_checkins': stats.get('total_checkins'),
			'total_reward': round((stats.get('total_quota') or 0) / unit, 2),
		}
	except Exception as e:
		return {'name': account.name, 'success': False, 'error': f'{type(e).__name__}: {e}'[:150]}



def add_checkin_log(msg: str):
	_checkin_add_log(checkin_state, 'CHECKIN', msg)


def save_checkin_state():
	"""持久化签到状态到文件"""
	_checkin_save(checkin_state, CHECKIN_STATE_FILE, 'CHECKIN')


def load_checkin_state():
	"""服务启动时从文件恢复签到状态（仅用于前端展示历史进度）"""
	_checkin_load(checkin_state, CHECKIN_STATE_FILE, 'CHECKIN')


async def run_login_checkin(trigger: str = 'manual'):
	"""执行 Login 账号签到流程：随机顺序，逐个签到，账号之间随机等待 30~60 分钟。

	所有账号都会被签到，可中途停止（设置 checkin_state['running'] = False）。
	"""
	accounts = load_login_accounts()
	if not accounts:
		add_checkin_log('没有 Login 账号，签到流程结束')
		checkin_state['running'] = False
		return

	# 随机打乱顺序，但保证每个账号都会被处理
	order = accounts[:]
	random.shuffle(order)

	today = datetime.now().strftime('%Y-%m-%d')
	checkin_state['running'] = True
	checkin_state['date'] = today
	checkin_state['trigger'] = trigger
	checkin_state['started_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	checkin_state['finished_at'] = None
	checkin_state['total'] = len(order)
	checkin_state['done'] = 0
	checkin_state['order'] = [a.name for a in order]
	checkin_state['current'] = None
	checkin_state['next_at'] = None
	checkin_state['accounts'] = {
		a.name: {'status': 'pending', 'message': '等待签到', 'time': None} for a in order
	}
	checkin_state['logs'] = []
	add_checkin_log(f'开始签到流程（{trigger}），共 {len(order)} 个账号，随机顺序')
	save_checkin_state()

	# 队列模型：失败的账号排到队尾稍后重试，确保所有账号都签到完。
	# 每次签到之间（含重试）随机等待 30~60 分钟，那时按 IP 的限流早已恢复。
	from collections import deque

	MAX_ATTEMPTS = 3
	queue = deque((acc, 1) for acc in order)
	processed_any = False

	async def _wait_between():
		"""签到间随机等待，分段睡眠以便及时响应停止"""
		checkin_state['current'] = None
		delay = checkin_gap_seconds()
		next_time = datetime.now().timestamp() + delay
		checkin_state['next_at'] = datetime.fromtimestamp(next_time).strftime('%Y-%m-%d %H:%M:%S')
		add_checkin_log(f'下一个账号将在 {delay // 60} 分钟后（{checkin_state["next_at"]}）签到')
		save_checkin_state()
		for _ in range(delay):
			if not checkin_state['running']:
				break
			await asyncio.sleep(1)

	while queue:
		if not checkin_state['running']:
			add_checkin_log('收到停止指令，签到流程中断')
			break

		acc, attempt = queue.popleft()

		# 除第一个账号外，每个账号签到前先等待
		if processed_any:
			await _wait_between()
			if not checkin_state['running']:
				add_checkin_log('收到停止指令，签到流程中断')
				break
		processed_any = True

		checkin_state['current'] = acc.name
		checkin_state['next_at'] = None
		save_checkin_state()

		result = await sign_in_login(acc)

		ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		if result.get('success'):
			status = 'already' if result.get('already_signed') else 'signed'
			msg = result.get('message', '签到成功')
			# 登录响应里带余额，顺便记录，供前端展示（无需再单独查登录接口）
			checkin_state['accounts'][acc.name] = {
				'status': status,
				'message': msg,
				'time': ts,
				'quota': result.get('quota'),
				'used': result.get('used'),
			}
			# 把本次拿到的余额写入今日用量快照（Login 账号余额仅在此处获取，不再单独查登录接口）
			if result.get('quota') is not None:
				record_account_usage('agentrouter', acc.name, result.get('used', 0), result.get('quota', 0))
			add_checkin_log(f'{acc.name}: {msg}')
		else:
			msg = result.get('message', '签到失败')
			if attempt < MAX_ATTEMPTS:
				# 标记为待重试，排到队尾
				queue.append((acc, attempt + 1))
				checkin_state['accounts'][acc.name] = {
					'status': 'pending',
					'message': f'{msg}（第 {attempt} 次失败，稍后重试）',
					'time': ts,
				}
				add_checkin_log(f'{acc.name}: {msg} — 已排入重试队列（{attempt}/{MAX_ATTEMPTS}）')
			else:
				checkin_state['accounts'][acc.name] = {'status': 'failed', 'message': msg, 'time': ts}
				add_checkin_log(f'{acc.name}: {msg} — 已达最大重试次数，放弃')
		save_checkin_state()

	checkin_state['running'] = False
	checkin_state['current'] = None
	checkin_state['next_at'] = None
	checkin_state['finished_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	signed = sum(1 for v in checkin_state['accounts'].values() if v['status'] in ('signed', 'already'))
	add_checkin_log(f'签到流程结束：{signed}/{checkin_state["total"]} 个账号已签到')
	save_checkin_state()


def start_login_checkin(trigger: str = 'manual') -> bool:
	"""启动签到任务，若已在运行则返回 False"""
	if checkin_state['running']:
		return False
	checkin_state['task'] = asyncio.create_task(run_login_checkin(trigger))
	return True


# ========== 每日自动签到开关 ==========

# AnyRouter / AgentRouter 是否开启每日 0 点自动签到（持久化到 checkin_settings.json）。
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
	"""每日 0 点自动启动 AgentRouter（Login）+ AnyRouter（cookie）+ 所有通用 new-api 站点的签到。

	AnyRouter/AgentRouter 受 checkin_settings 控制，new-api 站点受各自的 auto_checkin 控制；
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
				print('[ANYROUTER] AnyRouter 每日自动签到已关闭，跳过')
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


# ========== AnyRouter（cookie/session 方式）签到与续期 ==========


def load_cookie_accounts() -> list[AccountItem]:
	"""从 saved_config.json 加载 cookie/session 方式账号列表"""
	if not CONFIG_FILE.exists():
		return []
	try:
		data = _read_json_cached(CONFIG_FILE)
		accounts = data.get('accounts', []) if isinstance(data, dict) else data
		return [AccountItem(**a) for a in accounts]
	except Exception as e:
		print(f'[ANYROUTER] 加载 cookie 账号失败: {e}')
		return []


def _session_expiry_info(session: str) -> dict | None:
	"""解码 gorilla securecookie，算出 session 的过期时间与剩余天数。

	cookie 整体是 base64url(时间戳|gob|HMAC)，首段为签名时刻(unix 秒)，有效期 30 天。
	"""
	try:
		raw = base64.urlsafe_b64decode(session + '=' * (-len(session) % 4))
		ts = int(raw.split(b'|')[0])
		if ts < 1_000_000_000:
			return None
		exp = ts + 2592000  # MaxAge 30 天
		days = (exp - datetime.now().timestamp()) / 86400
		return {
			'expires_at': datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S'),
			'days_left': round(days, 1),
		}
	except Exception:
		return None


def _session_is_authenticated(session: str) -> bool | None:
	"""从 session cookie 本地判断它是否代表已登录身份。True/False 为确定结论，None 表示判不出来。

	gorilla securecookie 的载荷是 base64(时间戳|gob|HMAC)，gob 里是 gin session 的键值对明文
	（只签名不加密）。2026-08-09 实测两种 cookie 的差别很干净：

	  匿名（未登录时调 /api/oauth/state 得到）：176 字节，只有 oauth_state
	  已登录：496 字节，含 id / username / role / status / group / aff

	所以有 `id` 键即已登录。这样就不必为每个账号多打一次 /api/user/self —— 请求数直接决定
	会不会撞上 ESA 的 IP 限流，27 个账号能从 54 个请求降到 27 个。

	判不出来时返回 None 而不是 False：new-api 换了 session 结构的话，宁可退回打接口核实，
	也不要把好账号误报成"已失效，请重新登录"。
	"""
	try:
		raw = base64.urlsafe_b64decode(session + '=' * (-len(session) % 4))
		parts = raw.split(b'|')
		if len(parts) < 2:
			return None
		gob = base64.urlsafe_b64decode(parts[1] + b'=' * (-len(parts[1]) % 4))
	except Exception:
		return None
	if b'oauth_state' not in gob:
		return None  # 连预期的键都没有，说明结构变了，交给接口核实
	# gob 的字符串键以「长度字节 + 内容」编码，用 \x02id 精确匹配，避免撞上 username 里的 "id"
	return b'\x02id' in gob


def add_anyrouter_checkin_log(msg: str):
	_checkin_add_log(anyrouter_checkin_state, 'ANYROUTER', msg)


def save_anyrouter_checkin_state():
	"""持久化 AnyRouter 签到状态"""
	_checkin_save(anyrouter_checkin_state, ANYROUTER_CHECKIN_STATE_FILE, 'ANYROUTER')


def load_anyrouter_checkin_state():
	"""服务启动时恢复 AnyRouter 签到状态（仅用于前端展示历史进度）"""
	_checkin_load(anyrouter_checkin_state, ANYROUTER_CHECKIN_STATE_FILE, 'ANYROUTER')


async def run_anyrouter_checkin(trigger: str = 'manual'):
	"""执行 AnyRouter 签到：cookie 账号并发签到（Semaphore ANYROUTER_CONCURRENCY），数秒内完成。"""
	accounts = load_cookie_accounts()
	st = anyrouter_checkin_state
	today = datetime.now().strftime('%Y-%m-%d')
	st['running'] = True
	st['date'] = today
	st['trigger'] = trigger
	st['started_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	st['finished_at'] = None
	st['total'] = len(accounts)
	st['signed'] = 0
	st['already'] = 0
	st['failed'] = 0
	st['accounts'] = {a.name: {'status': 'pending', 'message': '等待签到', 'time': None} for a in accounts}
	st['logs'] = []
	add_anyrouter_checkin_log(f'开始 AnyRouter 签到（{trigger}），共 {len(accounts)} 个 cookie 账号')
	save_anyrouter_checkin_state()

	def _finish():
		st['signed'] = sum(1 for v in st['accounts'].values() if v['status'] == 'signed')
		st['already'] = sum(1 for v in st['accounts'].values() if v['status'] == 'already')
		st['failed'] = sum(1 for v in st['accounts'].values() if v['status'] == 'failed')
		st['running'] = False
		st['finished_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		add_anyrouter_checkin_log(
			f'AnyRouter 签到结束：成功 {st["signed"]} · 今日已签 {st["already"]} · 失败 {st["failed"]}'
		)
		save_anyrouter_checkin_state()

	if not accounts:
		add_anyrouter_checkin_log('没有 cookie 账号，AnyRouter 签到结束')
		_finish()
		return

	waf_cookies = await _get_waf_cookies_if_needed()
	if not waf_cookies:
		ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		for name in st['accounts']:
			st['accounts'][name] = {'status': 'failed', 'message': 'WAF cookies 获取失败', 'time': ts}
		add_anyrouter_checkin_log('WAF cookies 获取失败，AnyRouter 签到中止')
		_finish()
		return

	sem = asyncio.Semaphore(ANYROUTER_CONCURRENCY)

	async def _one(acc: AccountItem):
		async with sem:
			if not st['running']:
				return
			result = await sign_in(acc, waf_cookies)
			ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			if result.get('success'):
				status = 'already' if result.get('already_signed') else 'signed'
				st['accounts'][acc.name] = {'status': status, 'message': result.get('message', '签到成功'), 'time': ts}
			else:
				st['accounts'][acc.name] = {'status': 'failed', 'message': result.get('message', '签到失败'), 'time': ts}
			add_anyrouter_checkin_log(f'{acc.name}: {st["accounts"][acc.name]["message"]}')
			save_anyrouter_checkin_state()

	await asyncio.gather(*[_one(a) for a in accounts])
	_finish()


def start_anyrouter_checkin(trigger: str = 'manual') -> bool:
	"""启动 AnyRouter 签到任务，若已在运行则返回 False"""
	if anyrouter_checkin_state['running']:
		return False
	anyrouter_checkin_state['task'] = asyncio.create_task(run_anyrouter_checkin(trigger))
	return True


def _anyrouter_checkin_status_payload() -> dict:
	"""组装 AnyRouter 签到状态返回体"""
	st = anyrouter_checkin_state
	accounts = [
		{'name': name, 'status': info.get('status', 'pending'), 'message': info.get('message', ''), 'time': info.get('time')}
		for name, info in st['accounts'].items()
	]
	signed = sum(1 for a in accounts if a['status'] in ('signed', 'already'))
	failed = sum(1 for a in accounts if a['status'] == 'failed')
	return {
		'running': st['running'],
		'date': st['date'],
		'trigger': st['trigger'],
		'started_at': st['started_at'],
		'finished_at': st['finished_at'],
		'total': st['total'],
		'done': signed + failed,
		'signed': signed,
		'failed': failed,
		'accounts': accounts,
		'logs': st['logs'][-30:],
	}


# ========== 通用 new-api 站点签到调度 ==========
# 每个站点一份独立状态，存在 newapi_checkin_states[site_id]，持久化到站点自己的 state_file。


def newapi_state(site: NewapiSite) -> dict:
	"""取（或初始化）某站点的签到状态"""
	st = newapi_checkin_states.get(site.id)
	if st is None:
		st = _blank_checkin_state()
		newapi_checkin_states[site.id] = st
	return st


def add_newapi_checkin_log(site: NewapiSite, msg: str):
	_checkin_add_log(newapi_state(site), site.id.upper(), msg)


def save_newapi_checkin_state(site: NewapiSite):
	"""持久化签到状态"""
	_checkin_save(newapi_state(site), site.state_path(), site.id.upper())


def load_newapi_checkin_state(site: NewapiSite):
	"""服务启动时恢复签到状态（仅用于前端展示历史进度）"""
	_checkin_load(newapi_state(site), site.state_path(), site.id.upper())


async def run_newapi_checkin(site: NewapiSite, trigger: str = 'manual'):
	"""执行某站点的签到：token 账号并发签到（Semaphore 取站点 concurrency），数秒内完成。

	签到成功后顺便查一次余额写入今日快照，省去额外的查询请求。

	站点开着 Turnstile 时分两种情况：配置了打码平台 → 先用免费的 GET 预检剔除今日已签
	账号（token 按次计费，别替已签的白解），再逐账号求解并签到（全自动）；没配置 → 先
	探测一次并直接结束，把原因写进日志。站长关掉 Turnstile 后无需改代码，此路径自动恢复。
	"""
	accounts = load_newapi_accounts(site)
	st = newapi_state(site)
	today = datetime.now().strftime('%Y-%m-%d')
	st['running'] = True
	st['date'] = today
	st['trigger'] = trigger
	st['started_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	st['finished_at'] = None
	st['total'] = len(accounts)
	st['signed'] = 0
	st['already'] = 0
	st['failed'] = 0
	st['accounts'] = {a.name: {'status': 'pending', 'message': '等待签到', 'time': None} for a in accounts}
	st['logs'] = []
	add_newapi_checkin_log(site, f'开始 {site.label} 签到（{trigger}），共 {len(accounts)} 个 token 账号')
	save_newapi_checkin_state(site)

	def _finish():
		st['signed'] = sum(1 for v in st['accounts'].values() if v['status'] == 'signed')
		st['already'] = sum(1 for v in st['accounts'].values() if v['status'] == 'already')
		st['failed'] = sum(1 for v in st['accounts'].values() if v['status'] == 'failed')
		st['running'] = False
		st['finished_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		add_newapi_checkin_log(
			site, f'{site.label} 签到结束：成功 {st["signed"]} · 今日已签 {st["already"]} · 失败 {st["failed"]}'
		)
		save_newapi_checkin_state(site)
		# 失败推 webhook（默认关，设置页可开）——失败只在日志里等用户翻页发现不了
		if st['failed'] > 0 and notify_configured() and get_notify_config()['on_checkin_failed']:
			bad = [f'{name}：{v["message"][:60]}' for name, v in st['accounts'].items() if v['status'] == 'failed']

			async def _push_failure():
				r = await send_webhook_notify(f'❌ {site.label} 签到失败 {st["failed"]} 个', '\n'.join(bad))
				if not r.get('sent'):
					add_newapi_checkin_log(site, f'失败通知推送未发送：{r.get("error", "")}')

			_spawn(_push_failure())

	if not accounts:
		add_newapi_checkin_log(site, f'没有 {site.label} 账号，签到结束')
		_finish()
		return

	ts_state = await newapi_turnstile_status(site)
	ts_enabled = bool(ts_state['enabled'])
	ts_site_key = ts_state['site_key'] or ''
	if ts_enabled:
		solver_cfg = get_turnstile_solver_config()
		if not solver_cfg['api_key']:
			ts_msg = '站点已开启 Turnstile 人机校验且未配置打码平台，服务器端无法签到；请在设置页配置打码平台，或用 Web UI 的浏览器脚本签到'
			now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			for name in st['accounts']:
				st['accounts'][name] = {'status': 'failed', 'message': ts_msg, 'time': now_str}
			add_newapi_checkin_log(site, ts_msg)
			_finish()
			return
		if not ts_site_key:
			# 探测失败时 status 保守返回 enabled=True 但没有 sitekey，没东西可解，只能走浏览器
			ts_msg = '站点 Turnstile 状态探测失败拿不到 sitekey，无法服务器端求解；请稍后重试或用浏览器脚本签到'
			now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			for name in st['accounts']:
				st['accounts'][name] = {'status': 'failed', 'message': ts_msg, 'time': now_str}
			add_newapi_checkin_log(site, ts_msg)
			_finish()
			return
		add_newapi_checkin_log(
			site, f"站点开启 Turnstile，改用打码平台（{solver_cfg['provider'] or '自定义网关'}）逐账号求解 token"
		)
		page_url = site.domain.rstrip('/') + '/login'

	sem = asyncio.Semaphore(site.concurrency or NEWAPI_CONCURRENCY)
	if ts_enabled:
		# Turnstile token 按次计费：先用不挂中间件的 GET 状态把今日已签的剔掉，
		# 别替已签账号白解 token（与前端浏览器脚本的「先 sync 再生成」同一思路）。
		# 查询失败的账号按未签处理，宁可多花一次打码也不漏签。
		async def _preflight(acc: NewapiAccountItem):
			async with sem:
				return acc, await newapi_checkin_info(site, acc)

		pending: list[NewapiAccountItem] = []
		for acc, info in await asyncio.gather(*[_preflight(a) for a in accounts]):
			if info.get('success') and info.get('checked_in_today'):
				ts_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				st['accounts'][acc.name] = {'status': 'already', 'message': '今日已签（打码预检跳过）', 'time': ts_now}
			else:
				pending.append(acc)
		skipped = len(accounts) - len(pending)
		if skipped:
			add_newapi_checkin_log(site, f'打码预检：{skipped} 个账号今日已签，跳过求解')
		if not pending:
			_finish()
			return

	async def _one(acc: NewapiAccountItem):
		async with sem:
			if not st['running']:
				return
			ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			token = None
			if ts_enabled:
				solved = await solve_turnstile_token(ts_site_key, page_url)
				if not solved.get('success'):
					msg = f"过验失败: {solved.get('error', '未知错误')}"
					st['accounts'][acc.name] = {'status': 'failed', 'message': msg, 'time': ts}
					add_newapi_checkin_log(site, f'{acc.name}: {msg}')
					save_newapi_checkin_state(site)
					return
				token = solved['token']
			result = await sign_in_newapi(site, acc, turnstile_token=token)
			if result.get('success'):
				status = 'already' if result.get('already_signed') else 'signed'
				st['accounts'][acc.name] = {'status': status, 'message': result.get('message', '签到成功'), 'time': ts}
				bal = await query_balance_newapi(site, acc)
				if bal.get('success'):
					record_account_usage(site.id, acc.name, bal['used'], bal['quota'])
			else:
				st['accounts'][acc.name] = {'status': 'failed', 'message': result.get('message', '签到失败'), 'time': ts}
			add_newapi_checkin_log(site, f'{acc.name}: {st["accounts"][acc.name]["message"]}')
			save_newapi_checkin_state(site)

	await asyncio.gather(*[_one(a) for a in (pending if ts_enabled else accounts)])
	_finish()


def start_newapi_checkin(site: NewapiSite, trigger: str = 'manual') -> bool:
	"""启动某站点的签到任务，若已在运行则返回 False"""
	st = newapi_state(site)
	if st['running']:
		return False
	st['task'] = asyncio.create_task(run_newapi_checkin(site, trigger))
	return True


def _newapi_checkin_status_payload(site: NewapiSite) -> dict:
	"""组装签到状态返回体"""
	st = newapi_state(site)
	accounts = [
		{'name': name, 'status': info.get('status', 'pending'), 'message': info.get('message', ''), 'time': info.get('time')}
		for name, info in st['accounts'].items()
	]
	signed = sum(1 for a in accounts if a['status'] in ('signed', 'already'))
	failed = sum(1 for a in accounts if a['status'] == 'failed')
	return {
		'site_id': site.id,
		'running': st['running'],
		'date': st['date'],
		'trigger': st['trigger'],
		'started_at': st['started_at'],
		'finished_at': st['finished_at'],
		'total': st['total'],
		'done': signed + failed,
		'signed': signed,
		'failed': failed,
		'accounts': accounts,
		'logs': st['logs'][-30:],
	}


def save_renewed_sessions(updates: dict):
	"""把续期得到的新 session 批量写回 saved_config.json（按账号名匹配）"""
	if not updates or not CONFIG_FILE.exists():
		return
	try:
		data = json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
		accounts = data.get('accounts', []) if isinstance(data, dict) else data
		for a in accounts:
			if a.get('name') in updates:
				a.setdefault('cookies', {})['session'] = updates[a['name']]
		_atomic_write_json(CONFIG_FILE, data, indent=2)
	except Exception as e:
		print(f'[ANYROUTER] 写回续期 session 失败: {e}')


async def renew_one_cookie(account: AccountItem, waf_cookies: dict) -> dict:
	"""续期单个 cookie 账号的 session（+30 天）。

	调用 GET /api/oauth/state 触发服务端 session.Save() 重发 cookie。拿到新 cookie 后必须确认它
	仍代表已登录身份 —— 已过期的 session 打这个接口同样会 200 + 下发一个**匿名** cookie，写回去
	就把登录态弄丢了。优先用本地解码判断（零请求），只在解码判不出来时才打 /api/user/self 核实。
	"""
	base = ANYROUTER_CONFIG['domain']
	headers = {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': f'{base}/console',
		'Origin': base,
		ANYROUTER_CONFIG['api_user_key']: account.api_user,
		'Cache-Control': 'no-store',
	}
	try:
		all_cookies = {**waf_cookies, **account.cookies}
		resp = await anyrouter_request('GET', base + '/api/oauth/state', headers, cookies=all_cookies)
		blocked = anyrouter_block_reason(resp)
		if blocked:
			kind, why = blocked
			return {'name': account.name, 'success': False, 'message': f'续期失败 · {why}', 'blocked': kind}
		try:
			new_session = resp.cookies.get('session')
		except Exception:
			new_session = None
		if not new_session:
			return {'name': account.name, 'success': False, 'message': '续期接口未下发新 cookie（接口可能已变更）'}

		# 本地解码判身份：匿名 cookie 的 gob 里只有 oauth_state，登录 cookie 才带 id/username（已实测）
		authed = _session_is_authenticated(new_session)
		if authed is not True:
			# 解码判不出来（新版 new-api 可能换了 session 结构），退回打一次接口核实，别误判成失效
			check = await anyrouter_request(
				'GET', base + '/api/user/self', headers, cookies={**waf_cookies, 'session': new_session}
			)
			blocked = anyrouter_block_reason(check)
			if blocked:
				kind, why = blocked
				# 这里是核实请求被拦，不代表 cookie 有问题，别提示"重新登录"把人带偏
				return {
					'name': account.name,
					'success': False,
					'message': f'新 cookie 无法核实 · {why}',
					'blocked': kind,
				}
			ok = False
			try:
				cd = check.json()
				ok = bool(cd.get('success')) and cd.get('data', {}).get('id') is not None
			except Exception:
				ok = False
			if not ok:
				return {'name': account.name, 'success': False, 'message': 'cookie 已失效，无法续期，请重新登录'}
		info = _session_expiry_info(new_session) or {}
		return {
			'name': account.name,
			'success': True,
			'message': '续期成功',
			'new_session': new_session,
			'expires_at': info.get('expires_at'),
			'days_left': info.get('days_left'),
		}
	except Exception as e:
		return {'name': account.name, 'success': False, 'message': f'{type(e).__name__}: {e}'[:100]}


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

MIHOMO_CONFIG_FILE = Path(os.environ.get('MIHOMO_CONFIG') or Path.home() / 'mihomo' / 'config.yaml')
MIHOMO_GROUP = os.environ.get('MIHOMO_GROUP', '')  # mihomo 代理组名，出口轮换用；空 = 不轮换（行为安全降级）
# 组里混着信息项（剩余流量/官网）和子分组（自动选择/故障转移），还有全部不可达的 V6 节点，都跳过
MIHOMO_NODE_SKIP = re.compile(r'剩余流量|重置|到期|建议|官网|自动选择|故障转移|V6')
WAF_BATCH_SIZE = 4  # 单个出口 IP 每轮最多查几个（实测 ~8 个触发滑块，留余量给重试）
WAF_ROUND_GAP = 4  # 换了新出口 IP 时，轮与轮之间的间隔秒数
WAF_DEGRADED_GAP = 20  # 没有轮换可用（同 IP 硬扛）时的间隔秒数
WAF_IP_BUDGET = 6  # 单个出口 IP 在整轮查询里的请求预算（实测 ~8 触发滑块）
WAF_COOLDOWN = 45  # 所有出口 IP 都花光预算时的冷却秒数（等 WAF 计数窗口滑过）
WAF_MAX_ATTEMPTS = 3  # 单个账号最多尝试次数（cookie 被滑块标记后要重登，反复被拦就放弃）
WAF_DEADLINE = 420  # 整轮查询的时长上限（秒），超时把剩余账号报错返回
WAF_ABORT_STREAK = 8  # 连续这么多个账号被拦且零成功就提前中止：再打只是给惩罚窗口续命
WAF_PASS_CACHE_TTL = 30 * 60  # 「哪些节点能过 WAF」的探测结果缓存（探测要 1~2 分钟，别每次点都来）
_waf_pass_cache: dict = {'ts': 0.0, 'nodes': [], 'ips': []}
_balances_query_lock = asyncio.Lock()  # 轮换出口是全局动作，同时只能跑一轮查询


def _mihomo_controller() -> tuple[str, str] | None:
	"""从 mihomo 配置读 (controller 地址, secret)；读不到返回 None（此时不轮换）。"""
	try:
		text = MIHOMO_CONFIG_FILE.read_text(encoding='utf-8')
	except OSError:
		return None
	addr = secret = None
	for line in text.splitlines():
		if addr is None and line.startswith('external-controller:'):
			addr = line.split(':', 1)[1].strip()
		elif secret is None and line.startswith('secret:'):
			secret = line.split(':', 1)[1].strip().strip('\'"')
	if not addr:
		return None
	host, _, port = addr.rpartition(':')
	host = host.strip('[]')
	if host in ('0.0.0.0', '::', ''):
		host = '127.0.0.1'
	return f'http://{host}:{port}', secret or ''


def _mihomo_call(method: str, url: str, secret: str, body: dict | None = None):
	"""同步调 mihomo controller；异常返回 None（本地服务，失败就当不可用）。"""
	from curl_cffi import requests as cffi_requests

	try:
		return cffi_requests.request(
			method, url, headers={'Authorization': f'Bearer {secret}'}, json=body, timeout=8,
		)
	except Exception:
		return None


async def _query_egress_ip() -> str | None:
	"""当前代理出口的公网 IP。切完节点必须核对它 —— 节点名不同 ≠ 出口 IP 不同
	（实测原生 03/04 同 IP，专线 01/02 与 IPLC06 同 IP）。"""
	from curl_cffi import requests as cffi_requests

	proxies = {'https': _LOCAL_PROXY, 'http': _LOCAL_PROXY}

	def _do():
		for url in ('https://api.ip.sb/ip', 'https://ifconfig.me/ip'):
			try:
				r = cffi_requests.get(url, proxies=proxies, timeout=6)
				if r.status_code == 200 and r.text.strip():
					return r.text.strip()
			except Exception:
				continue
		return None

	return await asyncio.get_running_loop().run_in_executor(_UPSTREAM_POOL, _do)


async def _probe_exit_passes_waf() -> bool:
	"""匿名探测当前出口能否过 agentrouter 的 WAF。

	打 /api/user/self 但带一次性假 cookie —— 即使被滑块标记，标记的也是这个假 cookie，
	不伤真账号的 session。拿到 JSON（401 也算）= 放行；滑块页/429/不可达 = 不放行。
	实测（2026-08-22）：原生/家宽/专线 IP 基本都过，廉价数据中心（Vless 系）被拦，
	与地区无关 —— 所以轮换池不挑地区，谁能过用谁。
	"""
	from curl_cffi import requests as cffi_requests

	def _do():
		try:
			r = cffi_requests.get(
				f'{AGENTROUTER_ORG_CONFIG["domain"]}{AGENTROUTER_ORG_CONFIG["user_info_path"]}',
				headers={
					'User-Agent': USER_AGENT,
					'Accept': 'application/json, text/plain, */*',
					'new-api-user': '1',
					'Authorization': 'Bearer probe',
					'cookie': 'session=probe',
				},
				proxies={'https': _AGENTROUTER_PROXY, 'http': _AGENTROUTER_PROXY},
				impersonate='chrome131',
				timeout=6,
			)
			return agentrouter_block_reason(r) is None
		except Exception:
			return False

	return await asyncio.get_running_loop().run_in_executor(_UPSTREAM_POOL, _do)


class _MihomoGroupSwitcher:
	"""mihomo 代理组切换的公共底座：controller 定位、API 封装、原节点记忆与恢复。

	ExitRotator（余额/全签的 WAF 出口轮换）与 _KeysExitRotator（取密钥撞限流换出口）
	共用这套机制，差别只在「怎么挑下一个节点」的策略（子类实现）。
	"""

	def __init__(self):
		self._base, self._secret = None, None
		self._original = None
		self._nodes: list[str] = []
		self._idx = -1
		self._touched = False

	async def _api(self, method: str, path: str, body: dict | None = None):
		resp = await asyncio.get_running_loop().run_in_executor(
			_UPSTREAM_POOL, _mihomo_call, method, f'{self._base}{path}', self._secret, body,
		)
		if resp is None or resp.status_code >= 300:
			return None
		if method == 'GET':
			try:
				return resp.json()
			except Exception:
				return None
		return {}

	async def _select(self, node: str) -> bool:
		ok = await self._api('PUT', f'/proxies/{quote(MIHOMO_GROUP)}', {'name': node})
		if ok is not None:
			self._touched = True
		return ok is not None

	async def restore(self) -> None:
		if self._touched and self._original:
			if await self._select(self._original):
				global _exit_generation
				_exit_generation += 1  # 恢复原节点后同样要重新建连
			self._touched = False


class ExitRotator(_MihomoGroupSwitcher):
	"""查询期间轮换 mihomo 出口 IP，结束后恢复原节点。

	候选是组里**全部真实节点**（不限地区）：按实际出口 IP 去重后逐个用匿名探针实测能否过
	agentrouter 的 WAF，能过的都进轮换池（2026-08-22 实测约 10 个独立 IP：香港原生/新加坡/
	日本专线/韩国家宽/美国原生与专线）。探测结果缓存 WAF_PASS_CACHE_TTL —— 探测要 1~2 分钟，
	而且探测本身也在消耗各 IP 的 WAF 配额。

	controller 读不到 / 凑不出能过的节点时 start() 返回 False，查询退化为「不换 IP 只分批」。
	探测要切节点（期间影响用户经 7890 的其它流量），限时 150 秒。
	"""

	def __init__(self):
		super().__init__()
		self._ips: list[str] = []

	@property
	def ip_count(self) -> int:
		return len(self._ips)

	async def start(self) -> bool:
		"""发现能过 WAF 的出口节点，记住原节点。优先用缓存。"""
		ctl = _mihomo_controller()
		if not ctl:
			return False
		self._base, self._secret = ctl
		info = await self._api('GET', f'/proxies/{quote(MIHOMO_GROUP)}')
		if not info or not info.get('all'):
			return False
		self._original = info.get('now')
		if _waf_pass_cache['nodes'] and time.time() - _waf_pass_cache['ts'] < WAF_PASS_CACHE_TTL:
			pairs = [(n, ip) for n, ip in zip(_waf_pass_cache['nodes'], _waf_pass_cache['ips']) if n in info['all'] and n != self._original]
			if pairs:
				# 缓存路径不再核对出口 IP（节点 IP 会漂移）；漂移导致撞上热 IP 由运行时的预算/热度记账兜底
				self._nodes = [n for n, _ in pairs]
				self._ips = [ip for _, ip in pairs]
				self._idx = -1
				return True
		used = set()
		if self._original:
			used.add(self._original)
		orig_ip = await _query_egress_ip()
		if orig_ip:
			used.add(orig_ip)  # 用户刚被拦过的 IP，别再拿它查询
		t0 = time.time()
		for name in info['all']:
			if time.time() - t0 > 150:
				break
			if MIHOMO_NODE_SKIP.search(name) or name in used:
				continue
			if not await self._select(name):
				continue
			ip = await _query_egress_ip()
			if not ip or ip in used:
				continue  # 不可达，或与已试过的节点同 IP（同 IP 的 WAF 行为相同）
			used.add(ip)
			if await _probe_exit_passes_waf():
				self._nodes.append(name)
				self._ips.append(ip)
		if not self._nodes:
			await self.restore()
			return False
		_waf_pass_cache.update(ts=time.time(), nodes=list(self._nodes), ips=list(self._ips))
		print(f'[AGENTROUTER] 出口探测完成：{len(self._ips)} 个能过 WAF 的独立 IP')
		self._idx = -1
		return True

	async def next_ip(self) -> None:
		"""切到下一个出口 IP；池子小就轮着用（轮与轮的间隔由调用方控制）。"""
		if not self._nodes:
			return
		self._idx = (self._idx + 1) % len(self._nodes)
		if await self._select(self._nodes[self._idx]):
			global _exit_generation
			_exit_generation += 1  # 逼后续请求重新建连，否则旧隧道还钉在上一个出口上

	@property
	def current(self) -> int:
		"""当前用的是第几个出口 IP（-1 表示还没切过）"""
		return self._idx


_FATAL_LOGIN_MARKS = ('密码', '封禁', '限流', '429')


async def _login_balance_one(account: LoginAccountItem, force: bool) -> dict:
	"""查单个账号余额。fatal=True 的失败（密码错/封禁/限流）换 IP 重试也没用。"""

	def _login_err(e: Exception) -> dict:
		msg = f'{e}'[:120]
		return {'name': account.name, 'success': False, 'error': msg, 'fatal': any(m in msg for m in _FATAL_LOGIN_MARKS)}

	try:
		cookies, user_id = await _agentrouter_session(account, force=force)
	except Exception as e:
		return _login_err(e)
	real, why = await agentrouter_real_balance(cookies, user_id)
	# 被 WAF 拦或被限流时当场重登也没用（拦的是 cookie/IP），只有 session 失效才值得马上重来
	if real is None and 'WAF' not in (why or '') and '限流' not in (why or ''):
		_agentrouter_key_sessions.pop(account.name, None)
		try:
			cookies, user_id = await _agentrouter_session(account)
		except Exception as e:
			return _login_err(e)
		real, why = await agentrouter_real_balance(cookies, user_id)
	if real is not None:
		return {
			'name': account.name,
			'success': True,
			'quota': real['quota'],
			'used': real['used'],
			'username': real['username'],
		}
	return {
		'name': account.name,
		'success': False,
		'error': f'读取余额失败：{why}'[:160],
		'fatal': '限流' in (why or ''),
	}


async def _run_with_rotation(
	accounts: list, work, initial_force: bool = False, on_result=None, should_stop=None
) -> tuple[list[dict], bool]:
	"""分批 + 轮换出口 IP 地跑 work(account, force)，返回 (与 accounts 同序的结果, 是否提前中止)。

	调度规则（都是 2026-08-22 实测出的 WAF 行为）：
	- 每个出口 IP 有 WAF_IP_BUDGET 的请求预算，花光就换下一个；全花光就冷却 WAF_COOLDOWN 秒；
	- 被 WAF 拦/超时的账号换 IP 重试（cookie 被滑块标记后重登是唯一解法），最多 WAF_MAX_ATTEMPTS 次；
	- 连续 WAF_ABORT_STREAK 个被拦零成功就提前中止：再打只是给惩罚窗口续命；
	- 整轮有 WAF_DEADLINE 的时长上限，超时把剩余账号明确报错（别让前端无限等）；
	- 只在真的轮换成功时才重试 —— 没有新 IP，同一 IP 上重试也过不去（实测）。

	work 返回的 dict 用 success / fatal / error(message) 表达结果，fatal=True 的失败换 IP 也没用；
	on_result 在每个账号到达终态时回调，签到流程用它更新进度面板；
	should_stop 每轮开始前询问一次，返回 True 就停 —— fast 全签靠它响应停止按钮。
	"""
	rotator = ExitRotator()
	rotated = await rotator.start()
	if rotated:
		print(f'[AGENTROUTER] 出口轮换就绪：{rotator.ip_count} 个 IP')
	todo = [(a, initial_force) for a in accounts]
	attempts = {a.name: 0 for a in accounts}
	final: dict[str, dict] = {}
	ip_use = [0] * max(1, rotator.ip_count)
	deadline = time.time() + WAF_DEADLINE
	consec_fail = 0
	aborted = False
	try:
		while todo and time.time() < deadline and not aborted:
			if should_stop and should_stop():
				for a, _ in todo:
					final[a.name] = {'name': a.name, 'success': False, 'error': '已手动停止', 'message': '已手动停止'}
				todo.clear()
				break
			if rotated:
				# 挑一个还有预算的出口 IP；全热就冷却一轮（不消耗账号）
				for _ in range(len(ip_use)):
					await rotator.next_ip()
					if ip_use[rotator.current] < WAF_IP_BUDGET:
						break
				else:
					print(f'[AGENTROUTER] 出口 IP 都到预算，冷却 {WAF_COOLDOWN}s')
					await asyncio.sleep(WAF_COOLDOWN)
					ip_use = [0] * len(ip_use)
					continue
			chunk, todo = todo[:WAF_BATCH_SIZE], todo[WAF_BATCH_SIZE:]
			outcomes = await asyncio.gather(*[work(a, f) for a, f in chunk])
			cur = rotator.current if rotated else 0
			# 被 WAF 拦/连接超时说明这个 IP 已经热了，额外记账让下一轮尽快换掉它
			hot = sum(
				1
				for r in outcomes
				if not r.get('success') and any(
					m in (r.get('error') or r.get('message') or '') for m in ('WAF', 'Failed to perform')
				)
			)
			ip_use[cur] += len(chunk) + hot
			for (account, _), r in zip(chunk, outcomes):
				attempts[account.name] += 1
				consec_fail = 0 if r.get('success') else consec_fail + 1
				if r.get('success') or r.get('fatal') or not rotated or attempts[account.name] >= WAF_MAX_ATTEMPTS:
					final[account.name] = r
					if on_result:
						on_result(account, r)
				else:
					todo.append((account, True))
			if consec_fail >= WAF_ABORT_STREAK:
				aborted = True
				print(f'[AGENTROUTER] 连续 {consec_fail} 个账号被拦且零成功，提前中止（WAF 惩罚期）')
			elif todo:
				await asyncio.sleep(WAF_ROUND_GAP if rotated else WAF_DEGRADED_GAP)
		for a in accounts:
			if a.name not in final:
				msg = (
					'WAF 惩罚期（出口 IP 连续被拦），本次提前中止 —— 等 30~60 分钟再点一次重试即可，已完成的账号不受影响'
					if aborted
					else '超时未完成（出口 IP 都在 WAF 冷却），稍后再试'
				)
				final[a.name] = {'name': a.name, 'success': False, 'error': msg, 'message': msg}
	finally:
		await rotator.restore()
	return [final[a.name] for a in accounts], aborted


async def _query_login_balances(accounts: list, live: bool) -> list[dict]:
	"""余额查询的轮换封装（work 见 _login_balance_one，调度见 _run_with_rotation）"""
	results, _ = await _run_with_rotation(accounts, _login_balance_one, initial_force=live)
	return results


async def _sign_in_one(account: LoginAccountItem, force: bool) -> dict:
	"""一键全签轮换调度里的单个账号。

	agentrouter **登录即签到**，sign_in_login 每次都是全新登录，force 参数没有额外作用，
	保留它是为了与 _run_with_rotation 的 work(account, force) 接口一致。
	密码错/封禁/限流这类失败换 IP 也没用（fatal），WAF/超时交给调度器换 IP 重试。
	"""
	try:
		r = await sign_in_login(account)
	except Exception as e:
		msg = f'{type(e).__name__}: {e}'[:120]
		return {'name': account.name, 'success': False, 'error': msg, 'message': msg, 'fatal': True}
	msg = str(r.get('message') or '')
	out = {'name': account.name, **r}
	out['fatal'] = any(m in msg for m in _FATAL_LOGIN_MARKS)
	return out


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


class TurnstileSolverRequest(BaseModel):
	"""打码平台 / FlareSolverr 配置。api_key 留空表示保留已保存的值（前端不回显密钥）。"""

	provider: str
	api_key: str = ''
	base_url: str = ''
	flaresolverr_url: str = ''


@app.get('/api/turnstile/solver')
async def turnstile_solver_status():
	"""打码平台 / FlareSolverr 配置状态。api_key 只回是否已配置，绝不回显。"""
	cfg = get_turnstile_solver_config()
	return {
		'success': True,
		'solver': {
			'provider': cfg['provider'],
			'base_url': cfg['base_url'],
			'configured': bool(cfg['api_key'] and cfg['base_url'] and cfg['task_type']),
			'flaresolverr_url': get_flaresolverr_url(),
			'presets': {name: p['base_url'] for name, p in TURNSTILE_SOLVER_PRESETS.items()},
			'stats': _solver_stats(),
		},
	}


@app.post('/api/turnstile/solver')
async def save_turnstile_solver(req: TurnstileSolverRequest):
	"""保存打码平台 / FlareSolverr 配置（合并写 saved_config.json，不动其他段）"""
	provider = req.provider.strip().lower()
	if provider != 'custom' and provider not in TURNSTILE_SOLVER_PRESETS:
		return {'success': False, 'error': f'未知平台: {req.provider}（可选 2captcha / yescaptcha / capsolver / custom）'}
	try:
		data = dict(_read_json_cached(CONFIG_FILE) or {}) if CONFIG_FILE.exists() else {}
	except Exception:
		data = {}
	saved = data.get('turnstile_solver') or {}
	data['turnstile_solver'] = {
		'provider': provider,
		'api_key': req.api_key.strip() or saved.get('api_key') or '',
		'base_url': req.base_url.strip(),
		'flaresolverr_url': req.flaresolverr_url.strip(),
	}
	_atomic_write_json(CONFIG_FILE, data, indent=2)
	return {'success': True, 'message': '打码平台配置已保存'}


@app.post('/api/protection/test')
async def protection_test(site_id: str = ''):
	"""探测某站点挂了哪些防护层，并现场验证突破手段是否可用。

	首页裸探测只反映「当前这次响应」的防护（部分站点仅对 API 或按负载触发质询），
	结果是最保守的分类；运行期 newapi_request 撞到防护都会自动过验重试。
	solved 里 None 表示撞到了但没配求解器（CF 质询需 FlareSolverr）。
	"""
	sites = load_newapi_sites()
	if site_id:
		site = next((s for s in sites if s.id == site_id), None)
		if site is None:
			return {'success': False, 'error': f'未知站点: {site_id}'}
	else:
		if not sites:
			return {'success': False, 'error': '没有站点可探测'}
		site = sites[0]
	domain = site.domain.rstrip('/')

	page = await probe_page_protection(domain)
	ts = await newapi_turnstile_status(site)
	protections = {
		'cf_challenge': bool(page.get('cf_challenge')),
		'aliyun_waf': bool(page.get('aliyun_waf')),
		'turnstile': bool(ts['enabled']),
	}
	solved: dict = {}
	if protections['aliyun_waf']:
		solved['aliyun_waf'] = bool(await solve_aliyun_waf(domain))
	if protections['cf_challenge']:
		if get_flaresolverr_url():
			solved['cf_challenge'] = bool(await solve_cf_challenge(domain))
		else:
			solved['cf_challenge'] = None
	return {
		'success': True,
		'site': site.label,
		'domain': site.domain,
		'page_http_status': page.get('http_status'),
		'page_error': page.get('error'),
		'protections': protections,
		'solved': solved,
		'flaresolverr_configured': bool(get_flaresolverr_url()),
	}


@app.post('/api/turnstile/solver/test')
async def test_turnstile_solver(site_id: str = ''):
	"""实解一个 token 验证打码配置（会消耗一次打码费用，约 $0.001~0.002）。

	不指定站点时自动挑第一个开着 Turnstile 且有 sitekey 的站点。只求解不消费：
	token 不会拿去签到，纯验证 api_key、余额与网络链路是否可用。
	"""
	cfg = get_turnstile_solver_config()
	if not cfg['api_key']:
		return {'success': False, 'error': '请先保存 api_key'}
	sites = load_newapi_sites()
	site = None
	site_key = ''
	if site_id:
		site = next((s for s in sites if s.id == site_id), None)
		if site is None:
			return {'success': False, 'error': f'未知站点: {site_id}'}
		ts = await newapi_turnstile_status(site)
		if not ts['enabled']:
			return {'success': True, 'tested': False, 'message': f'{site.label} 未开启 Turnstile，无需打码'}
		if not ts['site_key']:
			return {'success': False, 'error': f'{site.label} 状态探测失败拿不到 sitekey'}
		site_key = ts['site_key']
	else:
		for s in sites:
			ts = await newapi_turnstile_status(s)
			if ts['enabled'] and ts['site_key']:
				site, site_key = s, ts['site_key']
				break
		if site is None:
			return {'success': False, 'error': '没有开着 Turnstile 的站点，没有可用于测试的 sitekey'}

	page_url = site.domain.rstrip('/') + '/login'
	started = time.monotonic()
	r = await solve_turnstile_token(site_key, page_url)
	elapsed = round(time.monotonic() - started, 1)
	if r.get('success'):
		return {'success': True, 'tested': True, 'site': site.label, 'elapsed': elapsed, 'token_preview': (r['token'] or '')[:24] + '…'}
	return {'success': False, 'tested': True, 'site': site.label, 'elapsed': elapsed, 'error': r.get('error')}


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


class _KeysExitRotator(_MihomoGroupSwitcher):
	"""取密钥撞限流时的轻量出口轮换。

	与 ExitRotator（agentrouter 专用，要探 WAF、能过的才进池）不同：这里撞的是站点自己的
	频控而不是 WAF，不挑节点，只要实际出口 IP 没用过就行。所有请求都走一次性新建连接，
	不存在 keep-alive 隧道钉死旧出口的问题（agentrouter 轮换踩过的坑）。
	（留在本模块：继承自代理域的 _MihomoGroupSwitcher，类继承要求定义期就绑定基类。）
	"""

	def __init__(self):
		super().__init__()
		self.tried_ips: set[str] = set()

	async def prepare(self) -> bool:
		"""读节点列表、记住原节点。mihomo 不可用时返回 False（调用方就不轮换）。"""
		ctl = _mihomo_controller()
		if not ctl:
			return False
		self._base, self._secret = ctl
		info = await self._api('GET', f'/proxies/{quote(MIHOMO_GROUP)}')
		if not info or not info.get('all'):
			return False
		self._original = info.get('now')
		self._nodes = [n for n in info['all'] if n != self._original and not MIHOMO_NODE_SKIP.search(n)]
		return True

	async def next_exit(self) -> bool:
		"""切到下一个没用过的节点（按实际出口 IP 去重 —— 多个节点共用出口很常见）。"""
		while self._idx + 1 < len(self._nodes):
			self._idx += 1
			if not await self._select(self._nodes[self._idx]):
				continue
			ip = await _query_egress_ip()
			if ip:
				if ip in self.tried_ips:
					continue
				self.tried_ips.add(ip)
			return True
		return False


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
