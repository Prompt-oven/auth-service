package com.promptoven.authservice.application.port.in;

public interface DHkeyExchangeUsecase {
	// Initialize DH for a new client session and return public key
	String initializeKeyExchange(String sessionId) throws Exception;

	// Complete the key exchange with client's public key
	void completeKeyExchange(String sessionId, String clientPublicKeyBase64) throws Exception;

	// Decrypt password received from client
	String decryptPassword(String sessionId, String encryptedPassword) throws Exception;

	// Clean up when session ends
	void cleanupSession(String sessionId);
}
