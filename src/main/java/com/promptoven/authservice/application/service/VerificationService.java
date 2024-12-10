package com.promptoven.authservice.application.service;

import java.util.Date;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.promptoven.authservice.application.port.in.dto.EmailCheckRequestDTO;
import com.promptoven.authservice.application.port.in.dto.EmailRequestRequestDTO;
import com.promptoven.authservice.application.port.in.dto.VerifyEmailRequestDTO;
import com.promptoven.authservice.application.port.in.dto.VerifyNicknameRequestDTO;
import com.promptoven.authservice.application.port.in.usecase.VerificationUseCase;
import com.promptoven.authservice.application.port.out.call.AuthTaskMemory;
import com.promptoven.authservice.application.port.out.call.MailSending;
import com.promptoven.authservice.application.port.out.call.MemberPersistence;
import com.promptoven.authservice.application.port.out.dto.AuthChallengeDTO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class VerificationService implements VerificationUseCase {

	private final MemberPersistence memberPersistence;
	private final AuthTaskMemory authTaskMemory;
	private final MailSending mailSending;
	@Value("${auth.challenge.expiration}")
	private long AUTH_CHALLENGE_EXPIRE_TIME;

	@Override
	public boolean checkMedia(EmailCheckRequestDTO emailCheckRequestDTO) {
		String email = emailCheckRequestDTO.getEmail();
		String code = emailCheckRequestDTO.getCode();
		if (authTaskMemory.getAuthChallenge(email).equals(code)) {
			saveSuccessAuthChallenge(email);
			return true;
		}
		return false;
	}

	protected void saveSuccessAuthChallenge(String email) {
		authTaskMemory.recordAuthChallengeSuccess(email, makeExpire());
	}

	private String makeRandomCode() {
		return String.format("%06d", new Random().nextInt(1000000));
	}

	private Date makeExpire() {
		return new Date(AUTH_CHALLENGE_EXPIRE_TIME + System.currentTimeMillis());
	}

	@Override
	public void requestEmail(EmailRequestRequestDTO emailRequestRequestDTO) {
		String email = emailRequestRequestDTO.getEmail();
		String code = makeRandomCode();
		CompletableFuture.runAsync(() -> mailSending.sendMail(email, "Email Verification Code", "Your verification code is " + code));
		authTaskMemory.recordAuthChallenge(AuthChallengeDTO.builder()
			.media(email)
			.code(code)
			.expires(makeExpire())
			.build());
	}

	@Override
	public void requestPhone(String phone) {
		String code = makeRandomCode();
		// todo: Send SMS or Kakaotalk Alert talk
		authTaskMemory.recordAuthChallenge(AuthChallengeDTO.builder()
			.media(phone)
			.code(code)
			.expires(makeExpire())
			.build());
	}

	@Override
	public boolean verifyEmail(VerifyEmailRequestDTO verifyEmailRequestDTO) {
		return !memberPersistence.existsByEmail(verifyEmailRequestDTO.getEmail());
	}

	//todo: 닉네임 중복 체크 통과하면 5분 정도 점유를 할 수 있도록 구현 (Redis Cache 사용)
	@Override
	public boolean verifyNickname(VerifyNicknameRequestDTO verifyNicknameRequestDTO) {
		return !memberPersistence.existsByNickname(verifyNicknameRequestDTO.getNickname());
	}
}
