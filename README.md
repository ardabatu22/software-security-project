# Secure Mobile Authentication — OAuth 2.0 Authorization Code + PKCE

University software-security term project. A secure demonstration of the
**OAuth 2.0 Authorization Code Flow + PKCE (S256)** using an iOS (SwiftUI) client and a
minimal Java (Spring Boot) backend. It also includes a scripted attack demo that proves
PKCE blocks the **authorization code interception** attack.

**Academic basis:** RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7519 (JWT), RFC 9700.

---

## Architecture

```
iOS App (SwiftUI)                         Backend (Spring Boot)
─────────────────                         ─────────────────────
AuthManager  ──(1) GET /authorize?code_challenge ─►  /authorize  → 302 redirect + code
   │                                                 (code is bound to the challenge)
   │ ◄── redirect: ...://callback?code&state ──────
   │
   └──────(2) POST /token (code + code_verifier) ─►  /token  → verify PKCE → JWT
   │ ◄── access_token (HS256 JWT) ─────────────────
   │
   └──────(3) GET /me  (Bearer JWT) ──────────────►  /me  → verify JWT → user info
```

**The core of PKCE:** the client generates a secret `code_verifier` and derives
`code_challenge = BASE64URL(SHA256(code_verifier))`. `/authorize` binds the issued code to
that challenge. At `/token` the server checks `BASE64URL(SHA256(code_verifier)) ==
code_challenge`, so an intercepted code alone is useless.

---

## Scope (deliberate simplifications)

Because this is a demo, the scope is intentionally narrow:

- A single **hardcoded user** (`demo_user` / `user-1`) and a single **hardcoded client**
  (`ios-demo-client`).
- **No database** — everything is in memory (`ConcurrentHashMap`).
- `/authorize` shows no login/consent screen; it **auto-approves** the one user.
- The JWT signing secret is a hardcoded constant (in production this would be an
  environment-provided secret / asymmetric key).
- HTTP over `localhost` (production would use HTTPS).

---

## Project Structure

```
securityproject/
├── backend/                              Java / Spring Boot (Maven)
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/example/oauth/
│       │   ├── OauthPkceApplication.java   Application entry point
│       │   ├── AuthController.java          /authorize, /token, /me (+ demo /token-legacy-insecure)
│       │   ├── DemoConfig.java              All hardcoded values
│       │   ├── JwtService.java              Issue/validate HS256 JWT (jjwt)
│       │   ├── PkceVerifier.java            BASE64URL(SHA256(verifier)) + constant-time compare
│       │   ├── CodeStore.java               In-memory code store (SecureRandom)
│       │   └── AuthorizationCode.java       One code: challenge + expiry + used flag
│       └── resources/application.properties (port 8080)
│
├── ios/                                  Swift / SwiftUI (XcodeGen)
│   ├── project.yml                       Definition that generates the Xcode project
│   └── OAuthDemo/
│       ├── OAuthDemoApp.swift            @main entry, injects AuthManager
│       ├── ContentView.swift             Single-screen UI
│       ├── AuthManager.swift             The entire OAuth/PKCE logic (ObservableObject)
│       ├── AuthConfig.swift              Client-side constants
│       ├── PKCEHelper.swift              verifier/challenge via CryptoKit
│       ├── KeychainHelper.swift          Store/read/delete the JWT in the Keychain
│       └── Info.plist                    URL scheme + ATS (localhost) exception
│
└── scripts/
    └── attack_demo.py                    PKCE attack/protection demo (3 scenarios)
```

---

## Backend — Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/authorize` | Validates client/PKCE, mints a code, **302**-redirects to `redirect_uri?code&state`. Returns JSON on error. |
| `POST` | `/token` | Takes `code` + `code_verifier`, **verifies PKCE**, returns a JWT on success. Code is single-use. |
| `GET`  | `/me` | Validates `Authorization: Bearer <jwt>`, returns user info (401 on error). |
| `POST` | `/token-legacy-insecure` | **DEMO ONLY — insecure.** Simulates a pre-PKCE server; does **not** check `code_verifier`. Used by the attack demo. |

**Key settings (`DemoConfig.java`):**
`client_id=ios-demo-client`, `redirect_uri=com.example.oauthdemo://callback`,
user `user-1`/`demo_user`, code TTL 60 s, JWT TTL 5 min (HS256), port 8080.

**Dependencies:** Spring Boot 3.3.5, Java 17, jjwt 0.12.6.

---

## How to Run

### 1) Backend

```bash
cd backend
mvn spring-boot:run
# runs on http://localhost:8080
```
> Requirements: JDK 17+ and Maven.

### 2) iOS app

```bash
# (only if you need to regenerate the project)
cd ios && xcodegen generate

open ios/OAuthDemo.xcodeproj
```
In Xcode pick an **iOS 16+ Simulator** and press **Run (⌘R)** with the backend running.
In the app: **Sign in** → the browser sheet flashes and closes → **"Signed in"** →
**Call /me** → **"Signed in as demo_user"** → **Logout**.

### 3) Attack demo (with the backend running)

```bash
python3 scripts/attack_demo.py
```
Three scenarios:
1. **Legacy (no-PKCE) server** → stolen code yields a token → `ATTACK SUCCEEDED`
2. **Real (PKCE) server**, wrong verifier → `invalid_grant` → `ATTACK BLOCKED`
3. **Legitimate client**, correct verifier → token → `LEGITIMATE EXCHANGE SUCCEEDED`
   (Succeeding with the same code also proves the failed attack did not "burn" it.)

---

## Quick Test with curl

```bash
# Generate a PKCE pair
VERIFIER=$(python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode())")
CHALLENGE=$(python3 -c "import hashlib,base64,sys; print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).rstrip(b'=').decode())" "$VERIFIER")

# 1) /authorize → grab the code from the 302 Location header
curl -v "http://localhost:8080/authorize?client_id=ios-demo-client&redirect_uri=com.example.oauthdemo://callback&state=xyz&code_challenge=$CHALLENGE&code_challenge_method=S256"

# 2) /token → JWT
CODE=<code from above>
curl -X POST http://localhost:8080/token -d "code=$CODE" -d "code_verifier=$VERIFIER" -d "client_id=ios-demo-client"

# 3) /me → user info
JWT=<access_token from above>
curl http://localhost:8080/me -H "Authorization: Bearer $JWT"
```

---

## Security Notes (for the defense)

- **PKCE S256** is compared on the server in constant time (`MessageDigest.isEqual`).
- Authorization code: **short-lived (60 s)**, **single-use**, cryptographically random.
- A failed PKCE attempt does not consume the code → the legitimate client can still use it.
- On iOS the JWT is stored in the **Keychain** (not UserDefaults).
- The client generates a `state` value for **CSRF** protection and requires it to match on return.
- `/token-legacy-insecure` and the hardcoded JWT secret are **demo-only** and must never exist in production.
