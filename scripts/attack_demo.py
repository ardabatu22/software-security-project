#!/usr/bin/env python3
"""
Authorization-code interception attack demo.

Shows, end to end, that PKCE (RFC 7636) defeats an intercepted authorization code:

  - On a legacy, pre-PKCE server the stolen code is enough to mint a token  -> ATTACK SUCCEEDS
  - On the PKCE-protected server the SAME stolen code is rejected           -> ATTACK BLOCKED
  - The legitimate client (which knows the code_verifier) still works       -> LEGIT SUCCEEDS

Run with the backend up on http://localhost:8080 :
    python3 scripts/attack_demo.py
"""

import base64
import hashlib
import http.client
import json
import secrets
import sys
import urllib.parse

HOST = "localhost"
PORT = 8080
CLIENT_ID = "ios-demo-client"
REDIRECT_URI = "com.example.oauthdemo://callback"

# ---- tiny ANSI helpers so the markers pop on screen for a live audience ----
BOLD = "\033[1m"; GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; DIM = "\033[2m"; RESET = "\033[0m"

def header(title):
    print(f"\n{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}{CYAN}{title}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")

def narrate(text):
    print(f"{YELLOW}» {text}{RESET}")

def request_line(text):
    print(f"{DIM}   {text}{RESET}")

def success_marker(text):
    print(f"{BOLD}{GREEN}*** {text} ***{RESET}")

def blocked_marker(text):
    print(f"{BOLD}{RED}*** {text} ***{RESET}")


# ---- minimal HTTP helpers (no external deps, and no auto-following of 302) ----
def http_get_no_redirect(path):
    conn = http.client.HTTPConnection(HOST, PORT)
    conn.request("GET", path)
    r = conn.getresponse()
    body = r.read().decode()
    headers = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return r.status, headers, body

def http_post_form(path, fields):
    body = urllib.parse.urlencode(fields)
    conn = http.client.HTTPConnection(HOST, PORT)
    conn.request("POST", path, body, {"Content-Type": "application/x-www-form-urlencoded"})
    r = conn.getresponse()
    resp = r.read().decode()
    conn.close()
    return r.status, resp


# ---- PKCE (client side) ----
def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def make_pkce():
    verifier = b64url(secrets.token_bytes(32))           # high-entropy code_verifier
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())  # S256 challenge
    return verifier, challenge


def decode_jwt_payload(token: str) -> dict:
    """Decode (not verify) the JWT payload just to display who the token is for."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # restore base64 padding
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}

def show_token(label, resp_body):
    data = json.loads(resp_body)
    token = data["access_token"]
    claims = decode_jwt_payload(token)
    print(f"   {label} HTTP 200, token_type={data.get('token_type')}")
    print(f"   access_token = {token[:40]}…{token[-10:]}")
    print(f"   JWT claims   = sub={claims.get('sub')!r}, username={claims.get('username')!r}")


def main():
    header("AUTHORIZATION-CODE INTERCEPTION ATTACK DEMO  (PKCE, RFC 7636)")
    print("Backend under test: http://%s:%d" % (HOST, PORT))

    # --- Step 1: legitimate client creates a PKCE pair ---
    header("STEP 1 — Legitimate client generates a PKCE pair")
    verifier, challenge = make_pkce()
    narrate("Only the real client knows the secret 'code_verifier'.")
    print(f"   code_verifier  (SECRET, stays on device) = {verifier}")
    print(f"   code_challenge (public, = S256(verifier)) = {challenge}")

    # --- Step 2: authorize + the attacker intercepts the code ---
    header("STEP 2 — /authorize  →  attacker intercepts the returned code")
    query = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": "demo-state-123",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    request_line(f"GET /authorize?{query}")
    status, headers, _ = http_get_no_redirect("/authorize?" + query)
    if status != 302:
        print(f"{RED}Unexpected status {status} from /authorize (is the backend running?){RESET}")
        sys.exit(1)
    location = headers.get("location", "")
    request_line(f"302 Location: {location}")
    stolen_code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    narrate("An attacker has intercepted this authorization code:")
    print(f"   stolen code = {stolen_code}")

    # --- Scenario 1: vulnerable, pre-PKCE server ---
    header("SCENARIO 1 — Attacker hits a LEGACY, pre-PKCE server (no verifier check)")
    narrate("Attacker submits the stolen code to /token-legacy-insecure with NO code_verifier.")
    request_line(f"POST /token-legacy-insecure  (code=<stolen>, client_id={CLIENT_ID})")
    status, body = http_post_form("/token-legacy-insecure",
                                  {"code": stolen_code, "client_id": CLIENT_ID})
    if status == 200:
        show_token("→", body)
        success_marker("ATTACK SUCCEEDED: stolen code exchanged for a token on a pre-PKCE server.")
    else:
        print(f"   Unexpected: HTTP {status} {body}")
        blocked_marker("Scenario 1 did not behave as expected.")

    # --- Scenario 2: PKCE-protected server, attacker has no/wrong verifier ---
    header("SCENARIO 2 — Attacker hits the REAL, PKCE-protected /token (wrong verifier)")
    narrate("Same stolen code, but the attacker does NOT know the code_verifier.")
    request_line("POST /token  (code=<stolen>, code_verifier=<attacker's guess>)")
    status, body = http_post_form("/token", {
        "code": stolen_code,
        "code_verifier": "attacker-does-not-know-the-real-verifier",
        "client_id": CLIENT_ID,
    })
    err = json.loads(body) if body else {}
    request_line(f"→ HTTP {status}: {err.get('error')} — {err.get('error_description')}")
    if status == 400 and err.get("error") == "invalid_grant":
        blocked_marker("ATTACK BLOCKED: PKCE verification failed, stolen code is useless.")
    else:
        print(f"   Unexpected: HTTP {status} {body}")

    # --- Scenario 3: legitimate client with the correct verifier ---
    header("SCENARIO 3 — Legitimate client redeems the SAME code with the real verifier")
    narrate("The real client proves possession of the code_verifier → exchange succeeds.")
    narrate("This also proves Scenario 2's failed attempt did NOT consume the code.")
    request_line("POST /token  (code=<same>, code_verifier=<correct secret>)")
    status, body = http_post_form("/token", {
        "code": stolen_code,
        "code_verifier": verifier,
        "client_id": CLIENT_ID,
    })
    if status == 200:
        show_token("→", body)
        success_marker("LEGITIMATE EXCHANGE SUCCEEDED: real client still works.")
    else:
        print(f"   Unexpected: HTTP {status} {body}")
        blocked_marker("Scenario 3 did not behave as expected.")

    # --- Wrap up ---
    header("SUMMARY")
    print(f"  {GREEN}Pre-PKCE server :{RESET} stolen code  → token   (vulnerable)")
    print(f"  {RED}PKCE server     :{RESET} stolen code  → REJECTED (protected)")
    print(f"  {GREEN}PKCE server     :{RESET} real client  → token   (still works)")
    print(f"\n{BOLD}Conclusion: PKCE binds the authorization code to a secret the attacker")
    print(f"never sees, so an intercepted code alone cannot be redeemed.{RESET}\n")


if __name__ == "__main__":
    main()
