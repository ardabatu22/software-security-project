package com.example.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * PKCE S256 verification (RFC 7636).
 *
 * The server recomputes BASE64URL(SHA256(code_verifier)) and checks it equals the
 * code_challenge that was stored at /authorize time. This is the heart of the demo.
 */
public final class PkceVerifier {

    private PkceVerifier() {}

    /** Returns BASE64URL-without-padding( SHA256( code_verifier ) ). */
    public static String computeS256Challenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to exist on every JVM; this should never happen.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Constant-time comparison of the recomputed challenge against the stored one.
     * Returns true only on an exact match.
     */
    public static boolean verify(String codeVerifier, String storedCodeChallenge) {
        String computed = computeS256Challenge(codeVerifier);
        return MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.US_ASCII),
                storedCodeChallenge.getBytes(StandardCharsets.US_ASCII));
    }
}
