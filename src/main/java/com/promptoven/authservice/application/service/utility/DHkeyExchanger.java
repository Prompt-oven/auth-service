package com.promptoven.authservice.application.service.utility;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DHkeyExchanger {
    private static final Logger logger = LoggerFactory.getLogger(DHkeyExchanger.class);
    private final KeyPair keyPair;
    private final KeyAgreement keyAgreement;
    
    // RFC 3526 MODP Group 14 (2048-bit)
    private static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    
    private static final BigInteger G = BigInteger.valueOf(2);
    private static final int KEY_SIZE = 2048; // Standard key size

    public DHkeyExchanger() throws GeneralSecurityException {
        try {
            // Create DH parameters with exact 2048-bit size
            DHParameterSpec dhParams = new DHParameterSpec(P, G, KEY_SIZE);

            // Generate key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhParams);
            this.keyPair = keyGen.generateKeyPair();

            // Initialize key agreement
            this.keyAgreement = KeyAgreement.getInstance("DH");
            this.keyAgreement.init(keyPair.getPrivate());
            
            logger.debug("DH key exchanger initialized with {} bit prime", KEY_SIZE);
        } catch (Exception e) {
            logger.error("Failed to initialize DH key exchanger", e);
            throw e;
        }
    }

    public byte[] getPublicKey() {
        try {
            DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
            BigInteger y = publicKey.getY();
            
            // Get the byte arrays for our values
            byte[] yBytes = y.toByteArray();
            byte[] pBytes = P.toByteArray();
            
            logger.debug("[DH] Public key Y length: {}", yBytes.length);
            logger.debug("[DH] Prime P length: {}", pBytes.length);
            
            // Calculate the actual sizes needed
            int sequenceSize = 4;  // First SEQUENCE header
            int innerSequenceSize = 3;  // Inner SEQUENCE
            int oidSize = 11;  // Object identifier
            int paramsSequenceSize = 3;  // Parameters SEQUENCE
            int primeSize = 3 + pBytes.length;  // Prime INTEGER
            int generatorSize = 3;  // Generator INTEGER
            int publicKeySize = 4 + yBytes.length;  // BIT STRING for public key
            
            int totalSize = sequenceSize + innerSequenceSize + oidSize + 
                           paramsSequenceSize + primeSize + generatorSize + publicKeySize;
            
            logger.debug("[DH] Total DER size needed: {}", totalSize);
            
            byte[] encoded = new byte[totalSize];
            int offset = 0;
            
            // Outer SEQUENCE
            encoded[offset++] = 0x30;
            encoded[offset++] = (byte) 0x82;
            encoded[offset++] = (byte) ((totalSize - 4) >> 8);
            encoded[offset++] = (byte) (totalSize - 4);
            
            // Inner SEQUENCE
            encoded[offset++] = 0x30;
            encoded[offset++] = (byte) 0x81;
            encoded[offset++] = (byte) (totalSize - 7);
            
            // Object Identifier for dhPublicKey
            encoded[offset++] = 0x06;
            encoded[offset++] = 0x09;
            encoded[offset++] = 0x2A;
            encoded[offset++] = (byte) 0x86;
            encoded[offset++] = 0x48;
            encoded[offset++] = (byte) 0x86;
            encoded[offset++] = (byte) 0xF7;
            encoded[offset++] = 0x0D;
            encoded[offset++] = 0x01;
            encoded[offset++] = 0x03;
            encoded[offset++] = 0x01;
            
            // Parameters SEQUENCE
            encoded[offset++] = 0x30;
            encoded[offset++] = (byte) 0x81;
            encoded[offset++] = (byte) (primeSize + generatorSize);
            
            // Prime INTEGER
            encoded[offset++] = 0x02;
            encoded[offset++] = (byte) 0x81;
            encoded[offset++] = (byte) pBytes.length;
            System.arraycopy(pBytes, 0, encoded, offset, pBytes.length);
            offset += pBytes.length;
            
            // Generator INTEGER
            encoded[offset++] = 0x02;
            encoded[offset++] = 0x01;
            encoded[offset++] = 0x02;
            
            // Public Key BIT STRING
            encoded[offset++] = 0x03;
            encoded[offset++] = (byte) 0x81;
            encoded[offset++] = (byte) yBytes.length;
            encoded[offset++] = 0x00;  // Leading zero
            System.arraycopy(yBytes, 0, encoded, offset, yBytes.length);
            
            logger.debug("[DH] Generated public key DER (hex): {}", bytesToHex(encoded));
            return encoded;
        } catch (Exception e) {
            logger.error("[DH] Failed to encode public key", e);
            throw new RuntimeException("Failed to encode public key", e);
        }
    }

    public byte[] generateSharedSecret(byte[] otherPublicKeyBytes) throws GeneralSecurityException {
        try {
            logger.debug("[DH] Received public key bytes (hex): {}", bytesToHex(otherPublicKeyBytes));
            
            // Find the last BIT STRING tag (0x03) in the DER structure
            int offset = otherPublicKeyBytes.length - 1;
            while (offset >= 0) {
                if (otherPublicKeyBytes[offset] == 0x03 &&  // BIT STRING tag
                    offset + 3 < otherPublicKeyBytes.length &&
                    (otherPublicKeyBytes[offset + 1] & 0xFF) == 0x81) {  // Length in long form
                    break;
                }
                offset--;
            }
            
            if (offset < 0) {
                throw new InvalidKeySpecException("BIT STRING tag not found in DER encoding");
            }
            
            // Skip BIT STRING tag and length bytes (0x03, 0x81, length, 0x00)
            offset += 4;
            
            // Extract the public key value
            byte[] yBytes = new byte[KEY_SIZE / 8];
            System.arraycopy(otherPublicKeyBytes, offset, yBytes, 0, yBytes.length);
            BigInteger y = new BigInteger(1, yBytes);
            
            logger.debug("[DH] Extracted Y value (hex): {}", y.toString(16));
            
            // Create public key
            DHPublicKeySpec keySpec = new DHPublicKeySpec(y, P, G);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey otherPublicKey = keyFactory.generatePublic(keySpec);
            
            // Validate and generate shared secret
            validatePublicKey((DHPublicKey) otherPublicKey);
            keyAgreement.doPhase(otherPublicKey, true);
            byte[] secret = keyAgreement.generateSecret();
            
            logger.debug("[DH] Generated shared secret length: {}", secret.length);
            logger.debug("[DH] Generated shared secret (hex): {}", bytesToHex(secret));
            
            return secret;
        } catch (Exception e) {
            logger.error("[DH] Failed to generate shared secret", e);
            throw new GeneralSecurityException("Failed to generate shared secret", e);
        }
    }

    private void validatePublicKey(DHPublicKey publicKey) throws InvalidKeyException {
        // Verify the key uses our parameters
        DHParameterSpec params = publicKey.getParams();
        if (!params.getP().equals(P) || !params.getG().equals(G)) {
            throw new InvalidKeyException("Invalid DH parameters");
        }

        // Verify the public key value is in range
        BigInteger y = publicKey.getY();
        if (y.compareTo(BigInteger.ONE) <= 0 || y.compareTo(P.subtract(BigInteger.ONE)) >= 0) {
            throw new InvalidKeyException("Invalid DH public key value");
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