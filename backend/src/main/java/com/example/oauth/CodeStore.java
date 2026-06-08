package com.example.oauth;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store of issued authorization codes (no database — demo scope).
 *
 * Maps an opaque random code string -> {@link AuthorizationCode}.
 */
@Component
public class CodeStore {

    private final ConcurrentHashMap<String, AuthorizationCode> codes = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder urlEncoder = Base64.getUrlEncoder().withoutPadding();

    /**
     * Generates a cryptographically random, URL-safe authorization code and stores it
     * bound to the given PKCE challenge.
     *
     * @return the new code string to hand back to the client
     */
    public String createCode(String codeChallenge, String codeChallengeMethod) {
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String code = urlEncoder.encodeToString(raw);

        long expiresAt = System.currentTimeMillis() + DemoConfig.AUTH_CODE_TTL_MILLIS;
        codes.put(code, new AuthorizationCode(codeChallenge, codeChallengeMethod, expiresAt));
        return code;
    }

    /** Looks up a code, or null if it was never issued. */
    public AuthorizationCode get(String code) {
        return codes.get(code);
    }

    /** Removes a code entirely (used after a successful, single-use redemption). */
    public void remove(String code) {
        codes.remove(code);
    }
}
