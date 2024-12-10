package com.promptoven.authservice.application.service;

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.promptoven.authservice.application.port.in.DHkeyExchangeUsecase;
import com.promptoven.authservice.application.service.utility.DHEncryption;
import com.promptoven.authservice.application.service.utility.DHkeyExchanger;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class DHKeyExchangeService implements DHkeyExchangeUsecase {

	// todo: 추후에 Garnet(replacement of Redis)로 변경 필요
	// Store DH instances for each client session
	private final Map<String, DHkeyExchanger> dhExchangers = new ConcurrentHashMap<>();
	// Store encryption instances after key exchange
	private final Map<String, DHEncryption> encryptionInstances = new ConcurrentHashMap<>();

	// Initialize DH for a new client session and return public key
	@Override
	public String initializeKeyExchange(String sessionId) throws Exception {
		DHkeyExchanger exchanger = new DHkeyExchanger();
		dhExchangers.put(sessionId, exchanger);
		return Base64.getEncoder().encodeToString(exchanger.getPublicKey());
	}

	// Complete the key exchange with client's public key
	@Override
	public void completeKeyExchange(String sessionId, String clientPublicKeyBase64) throws Exception {
		if (clientPublicKeyBase64 == null || clientPublicKeyBase64.trim().isEmpty()) {
			throw new IllegalArgumentException("Client public key cannot be null or empty");
		}

		DHkeyExchanger exchanger = dhExchangers.get(sessionId);
		if (exchanger == null) {
			throw new IllegalStateException("No key exchange initialized for this session");
		}

		try {
			byte[] clientPublicKey = Base64.getDecoder().decode(clientPublicKeyBase64.trim());
			byte[] sharedSecret = exchanger.generateSharedSecret(clientPublicKey);

			// Create encryption instance for this session
			DHEncryption encryption = new DHEncryption(sharedSecret);
			encryptionInstances.put(sessionId, encryption);

			// Clean up the exchanger as it's no longer needed
			dhExchangers.remove(sessionId);
		} catch (IllegalArgumentException e) {
			log.error("Invalid Base64 encoded public key: {}", clientPublicKeyBase64);
			throw new IllegalArgumentException("Invalid Base64 encoded public key: " + e.getMessage());
		} catch (Exception e) {
			log.error("Failed to complete key exchange: {}", e.getMessage());
			throw e;
		}
	}

	// Decrypt password received from client
	@Override
	public String decryptPassword(String sessionId, String encryptedPassword) throws Exception {
		DHEncryption encryption = encryptionInstances.get(sessionId);
		if (encryption == null) {
			throw new IllegalStateException("No encryption instance found for this session");
		}
		return encryption.decrypt(encryptedPassword);
	}

	// Clean up when session ends
	@Override
	public void cleanupSession(String sessionId) {
		dhExchangers.remove(sessionId);
		encryptionInstances.remove(sessionId);
	}
} 