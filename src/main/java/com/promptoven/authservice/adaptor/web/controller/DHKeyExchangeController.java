package com.promptoven.authservice.adaptor.web.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.promptoven.authservice.adaptor.web.util.BaseResponse;
import com.promptoven.authservice.application.port.in.DHkeyExchangeUsecase;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/v2/auth/key-exchange")
@RequiredArgsConstructor
public class DHKeyExchangeController {
	private final DHkeyExchangeUsecase dHkeyExchangeUsecase;

	@PostMapping("/init")
	public BaseResponse<String> initializeKeyExchange(
		@RequestHeader("X-Session-ID") String sessionId) throws Exception {
		log.debug("Initializing key exchange for session: {}", sessionId);
		String serverPublicKey = dHkeyExchangeUsecase.initializeKeyExchange(sessionId);
		log.debug("Key exchange initialized successfully for session: {}", sessionId);
		return new BaseResponse<>(serverPublicKey);
	}

	@PostMapping("/complete")
	public BaseResponse<Void> completeKeyExchange(
		@RequestHeader(value = "X-Session-ID", required = true) String sessionId,
		@RequestBody String clientPublicKey) throws Exception {
		if (clientPublicKey == null || clientPublicKey.trim().isEmpty()) {
			log.warn("Empty client public key received for session: {}", sessionId);
			throw new IllegalArgumentException("Client public key cannot be empty");
		}

		if (sessionId == null || sessionId.trim().isEmpty()) {
			log.warn("Empty session ID received");
			throw new IllegalArgumentException("Session ID cannot be empty");
		}

		try {
			log.debug("Completing key exchange for session: {}", sessionId);
			dHkeyExchangeUsecase.completeKeyExchange(sessionId, clientPublicKey);
			log.debug("Key exchange completed successfully for session: {}", sessionId);
			return new BaseResponse<>();
		} catch (Exception e) {
			log.error("Failed to complete key exchange for session {}: {}", sessionId, e.getMessage());
			throw e;
		}
	}

	@PostMapping("/destroy")
	public BaseResponse<Void> terminateDHKeySession(
		@RequestHeader("X-Session-ID") String sessionId) throws Exception {
		log.debug("Destroying key exchange session: {}", sessionId);
		dHkeyExchangeUsecase.cleanupSession(sessionId);
		log.debug("Key exchange session destroyed successfully: {}", sessionId);
		return new BaseResponse<>();
	}
}