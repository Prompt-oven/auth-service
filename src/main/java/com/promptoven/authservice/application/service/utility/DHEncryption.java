package com.promptoven.authservice.application.service.utility;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.AEADBadTagException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DHEncryption {
    private static final Logger logger = LoggerFactory.getLogger(DHEncryption.class);
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BYTES = GCM_TAG_LENGTH / 8;
    
    private final SecretKey secretKey;

    public DHEncryption(byte[] sharedSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(sharedSecret);
        this.secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        
        logger.debug("[Init] Shared secret length: {}", sharedSecret.length);
        logger.debug("[Init] Shared secret (hex): {}", bytesToHex(sharedSecret));
        logger.debug("[Init] Derived key length: {}", keyBytes.length);
        logger.debug("[Init] Derived key (hex): {}", bytesToHex(keyBytes));
    }

    public String encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        logger.debug("[Encrypt] Input text length: {}", plaintext.length());
        logger.debug("[Encrypt] Generated IV (hex): {}", bytesToHex(iv));

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        cipher.updateAAD(new byte[0]);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = Arrays.copyOfRange(encrypted, 0, encrypted.length - GCM_TAG_BYTES);
        byte[] tag = Arrays.copyOfRange(encrypted, encrypted.length - GCM_TAG_BYTES, encrypted.length);

        logger.debug("[Encrypt] Ciphertext length: {}", ciphertext.length);
        logger.debug("[Encrypt] Ciphertext (hex): {}", bytesToHex(ciphertext));
        logger.debug("[Encrypt] Tag length: {}", tag.length);
        logger.debug("[Encrypt] Tag (hex): {}", bytesToHex(tag));

        byte[] combined = new byte[iv.length + ciphertext.length + tag.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        System.arraycopy(tag, 0, combined, iv.length + ciphertext.length, tag.length);

        String result = Base64.getEncoder().encodeToString(combined);
        logger.debug("[Encrypt] Final combined length: {}", combined.length);
        logger.debug("[Encrypt] Final base64: {}", result);
        return result;
    }

    public String decrypt(String encryptedText) throws Exception {
        logger.debug("[Decrypt] Input base64: {}", encryptedText);
        
        byte[] combined = Base64.getDecoder().decode(encryptedText);
        byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_LENGTH, combined.length - GCM_TAG_BYTES);
        byte[] tag = Arrays.copyOfRange(combined, combined.length - GCM_TAG_BYTES, combined.length);

        logger.debug("[Decrypt] IV (hex): {}", bytesToHex(iv));
        logger.debug("[Decrypt] Ciphertext length: {}", ciphertext.length);
        logger.debug("[Decrypt] Ciphertext (hex): {}", bytesToHex(ciphertext));
        logger.debug("[Decrypt] Tag length: {}", tag.length);
        logger.debug("[Decrypt] Tag (hex): {}", bytesToHex(tag));

        byte[] encrypted = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, encrypted, 0, ciphertext.length);
        System.arraycopy(tag, 0, encrypted, ciphertext.length, tag.length);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        cipher.updateAAD(new byte[0]);

        try {
            byte[] decrypted = cipher.doFinal(encrypted);
            String result = new String(decrypted, StandardCharsets.UTF_8);
            logger.debug("[Decrypt] Decrypted text: {}", result);
            return result;
        } catch (AEADBadTagException e) {
            logger.error("[Decrypt] Authentication failed: {}", e.getMessage());
            throw new SecurityException("Password decryption failed: authentication tag mismatch");
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
} 