package com.pbl.starauthserver.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class JwtUtil {
    public static long ACCESS_TOKEN_EXPIRY = 15 * 60L;          // 15 minutes
    public static long REFRESH_TOKEN_EXPIRY = 24 * 60 * 60L;    // 1 day
    public static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
