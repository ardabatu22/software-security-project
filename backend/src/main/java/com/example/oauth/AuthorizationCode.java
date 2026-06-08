package com.example.oauth;

/**
 * One issued authorization code, held in memory until it is redeemed or expires.
 *
 * The key security property for PKCE: the code is bound to the {@code codeChallenge}
 * supplied at /authorize time. At /token time the client must prove it knows the
 * matching {@code code_verifier}, so a stolen code alone is useless.
 */
public class AuthorizationCode {

    private final String codeChallenge;       // BASE64URL(SHA256(code_verifier)), from /authorize
    private final String codeChallengeMethod; // always "S256" in this demo
    private final long expiresAtMillis;       // wall-clock expiry
    private boolean used;                      // single-use flag

    public AuthorizationCode(String codeChallenge, String codeChallengeMethod, long expiresAtMillis) {
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.expiresAtMillis = expiresAtMillis;
        this.used = false;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public boolean isExpired() {
        return System.currentTimeMillis() > expiresAtMillis;
    }

    public boolean isUsed() {
        return used;
    }

    public void markUsed() {
        this.used = true;
    }
}
