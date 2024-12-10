package com.promptoven.authservice.application.service.utility;

public class DHexample {
    public static void main(String[] args) throws Exception {
        // Server side
        DHkeyExchanger serverDH = new DHkeyExchanger();
        byte[] serverPublicKey = serverDH.getPublicKey();

        // Client side
        DHkeyExchanger clientDH = new DHkeyExchanger();
        byte[] clientPublicKey = clientDH.getPublicKey();

        // Generate shared secrets (same on both sides)
        byte[] serverSharedSecret = serverDH.generateSharedSecret(clientPublicKey);
        byte[] clientSharedSecret = clientDH.generateSharedSecret(serverPublicKey);

        // Create encryption utilities
        DHEncryption serverEncryption = new DHEncryption(serverSharedSecret);
        DHEncryption clientEncryption = new DHEncryption(clientSharedSecret);

        // Example encryption/decryption
        String originalText = "Hello, secure world!";
        String encrypted = serverEncryption.encrypt(originalText);
        String decrypted = clientEncryption.decrypt(encrypted);

        System.out.println("Original: " + originalText);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
