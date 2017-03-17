package com.easemob.stliu.github.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotNull;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * borrowed from https://github.com/airbnb/chancery/blob/master/src/main/java/com/airbnb/chancery/github/GithubAuthChecker.java
 */

@Slf4j
public final class GithubAuthChecker {
    private static final String HMAC_SHA1 = "HmacSHA1";
    private final Mac mac;


    public GithubAuthChecker(String secret)
            throws NoSuchAlgorithmException, InvalidKeyException {
        mac = Mac.getInstance(HMAC_SHA1);
        final SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(), HMAC_SHA1);
        mac.init(signingKey);
    }

    /**
     * Checks a github signature against its payload
     * @param signature A X-Hub-Signature header value ("sha1=[...]")
     * @param payload The signed HTTP request body
     * @return Whether the signature is correct for the checker's secret
     */
    public boolean checkSignature(String signature, @NotNull String payload) {
        if (signature == null || signature.length() != 45)
            return false;

        final char[] hash = Hex.encodeHex(this.mac.doFinal(payload.getBytes()));

        final String expected = "sha1=" + Arrays.toString(hash);

        log.debug("Comparing {} and {}", expected, signature);
        return expected.equals(signature);
    }
}
