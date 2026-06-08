# Secure Mobile Authentication — OAuth 2.0 Authorization Code + PKCE

Üniversite yazılım güvenliği dönem projesi. iOS (SwiftUI) istemci + minimal Java (Spring Boot)
backend ile **OAuth 2.0 Authorization Code Flow + PKCE (S256)** akışının güvenli bir gösterimi.
Ayrıca PKCE'nin **authorization code interception** saldırısını nasıl engellediğini kanıtlayan
bir saldırı demosu içerir.

**Akademik temel:** RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7519 (JWT), RFC 9700.

---

## Mimari

```
iOS App (SwiftUI)                         Backend (Spring Boot)
─────────────────                         ─────────────────────
AuthManager  ──(1) GET /authorize?code_challenge ─►  /authorize  → 302 redirect + code
   │                                                 (kod, challenge'a bağlanır)
   │ ◄── redirect: ...://callback?code&state ──────
   │
   └──────(2) POST /token (code + code_verifier) ─►  /token  → PKCE doğrula → JWT
   │ ◄── access_token (HS256 JWT) ─────────────────
   │
   └──────(3) GET /me  (Bearer JWT) ──────────────►  /me  → JWT doğrula → kullanıcı bilgisi
```

**PKCE'nin özü:** İstemci gizli bir `code_verifier` üretir, ondan `code_challenge =
BASE64URL(SHA256(code_verifier))` türetir. `/authorize` kodu bu challenge'a bağlar. `/token`
aşamasında sunucu `BASE64URL(SHA256(code_verifier)) == code_challenge` kontrolünü yapar; bu
yüzden tek başına çalınan bir kod işe yaramaz.

---

## Kapsam (bilinçli sadeleştirmeler)

Bu bir demo olduğu için kapsam kasıtlı olarak dardır:

- Tek **sabit kullanıcı** (`demo_user` / `user-1`), tek **sabit client** (`ios-demo-client`).
- **Veritabanı yok** — her şey bellekte (`ConcurrentHashMap`).
- `/authorize` login/consent ekranı göstermez; tek kullanıcıyı **otomatik onaylar**.
- JWT imzalama sırrı kodda sabit bir sabittir (gerçek üründe ortam değişkeni / asimetrik anahtar olurdu).
- HTTP `localhost` üzerinde (gerçek üründe HTTPS).

---

## Proje Yapısı

```
securityproject/
├── backend/                              Java / Spring Boot (Maven)
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/example/oauth/
│       │   ├── OauthPkceApplication.java   Uygulama girişi
│       │   ├── AuthController.java          /authorize, /token, /me (+ demo /token-legacy-insecure)
│       │   ├── DemoConfig.java              Tüm sabit değerler
│       │   ├── JwtService.java              HS256 JWT üret/doğrula (jjwt)
│       │   ├── PkceVerifier.java            BASE64URL(SHA256(verifier)) + sabit-zamanlı karşılaştırma
│       │   ├── CodeStore.java               Bellekte kod deposu (SecureRandom)
│       │   └── AuthorizationCode.java       Tek kod: challenge + expiry + used
│       └── resources/application.properties (port 8080)
│
├── ios/                                  Swift / SwiftUI (XcodeGen)
│   ├── project.yml                       Xcode projesini üreten tanım
│   └── OAuthDemo/
│       ├── OAuthDemoApp.swift            @main giriş, AuthManager enjeksiyonu
│       ├── ContentView.swift             Tek ekran UI
│       ├── AuthManager.swift             OAuth/PKCE mantığının tamamı (ObservableObject)
│       ├── AuthConfig.swift              İstemci sabitleri
│       ├── PKCEHelper.swift              CryptoKit ile verifier/challenge
│       ├── KeychainHelper.swift          JWT'yi Keychain'de sakla/oku/sil
│       └── Info.plist                    URL scheme + ATS (localhost) istisnası
│
└── scripts/
    └── attack_demo.py                    PKCE saldırı/koruma demosu (3 senaryo)
```

---

## Backend — Endpoint'ler

| Method | Path | Açıklama |
|--------|------|----------|
| `GET`  | `/authorize` | client/PKCE doğrular, kod üretir, **302** ile `redirect_uri?code&state`'e yönlendirir. Hatada JSON döner. |
| `POST` | `/token` | `code` + `code_verifier` alır, **PKCE doğrular**, başarılıysa JWT döner. Kod tek kullanımlık. |
| `GET`  | `/me` | `Authorization: Bearer <jwt>` doğrular, kullanıcı bilgisini döner (401'de hata). |
| `POST` | `/token-legacy-insecure` | **SADECE DEMO — güvensiz.** PKCE'siz eski sunucu taklidi; `code_verifier` kontrol etmez. Saldırı demosu için. |

**Temel ayarlar (`DemoConfig.java`):**
`client_id=ios-demo-client`, `redirect_uri=com.example.oauthdemo://callback`,
kullanıcı `user-1`/`demo_user`, kod ömrü 60 sn, JWT ömrü 5 dk (HS256), port 8080.

**Bağımlılıklar:** Spring Boot 3.3.5, Java 17, jjwt 0.12.6.

---

## Nasıl Çalıştırılır

### 1) Backend

```bash
cd backend
mvn spring-boot:run
# http://localhost:8080 üzerinde çalışır
```
> Gereksinim: JDK 17+ ve Maven. (Bu makinede Maven `brew install maven` ile kuruldu.)

### 2) iOS uygulaması

```bash
# (yalnızca projeyi yeniden üretmek gerekirse)
cd ios && xcodegen generate

open ios/OAuthDemo.xcodeproj
```
Xcode'da bir **iOS 16+ Simülatör** seç, backend çalışırken **Run (⌘R)**.
Uygulamada: **Sign in** → tarayıcı sheet'i kısa açılıp kapanır → **"Signed in"** →
**Call /me** → **"Signed in as demo_user"** → **Logout**.

### 3) Saldırı demosu (backend açıkken)

```bash
python3 scripts/attack_demo.py
```
Üç senaryo:
1. **Eski (PKCE'siz) sunucu** → çalınan kod token verir → `ATTACK SUCCEEDED`
2. **Gerçek (PKCE'li) sunucu**, yanlış verifier → `invalid_grant` → `ATTACK BLOCKED`
3. **Gerçek kullanıcı**, doğru verifier → token → `LEGITIMATE EXCHANGE SUCCEEDED`
   (Aynı kodla başarılı olması, başarısız saldırının kodu "yakmadığını" da kanıtlar.)

---

## curl ile Hızlı Test

```bash
# PKCE çifti üret
VERIFIER=$(python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode())")
CHALLENGE=$(python3 -c "import hashlib,base64,sys; print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).rstrip(b'=').decode())" "$VERIFIER")

# 1) /authorize → 302 Location içinden code'u al
curl -v "http://localhost:8080/authorize?client_id=ios-demo-client&redirect_uri=com.example.oauthdemo://callback&state=xyz&code_challenge=$CHALLENGE&code_challenge_method=S256"

# 2) /token → JWT
CODE=<yukarıdaki code>
curl -X POST http://localhost:8080/token -d "code=$CODE" -d "code_verifier=$VERIFIER" -d "client_id=ios-demo-client"

# 3) /me → kullanıcı bilgisi
JWT=<yukarıdaki access_token>
curl http://localhost:8080/me -H "Authorization: Bearer $JWT"
```

---

## Güvenlik Notları (savunma için)

- **PKCE S256** sunucuda sabit-zamanlı (`MessageDigest.isEqual`) karşılaştırılır.
- Authorization code: **kısa ömürlü (60 sn)**, **tek kullanımlık**, kriptografik rastgele.
- Başarısız PKCE denemesi kodu tüketmez → meşru istemci hâlâ kullanabilir.
- iOS'ta JWT **Keychain**'de (UserDefaults değil) saklanır.
- İstemci **CSRF** için `state` üretir ve dönüşte eşleşmesini zorunlu kılar.
- `/token-legacy-insecure` ve sabit JWT sırrı **yalnızca demo** içindir; üründe asla bulunmamalıdır.
```
