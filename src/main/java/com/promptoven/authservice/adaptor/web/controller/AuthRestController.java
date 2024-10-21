package com.promptoven.authservice.adaptor.web.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.promptoven.authservice.adaptor.web.controller.vo.in.ChangePWRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.EmailCheckRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.EmailRequestRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.LoginRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.OauthLoginRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.OauthRegisterRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.OauthUnregisterRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.RegisterRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.RegisterSocialRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.ResetPWRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.VerifyEmailRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.VerifyNicknameRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.out.LoginResponseVO;
import com.promptoven.authservice.adaptor.web.controller.vo.out.SocialLoginResponseVO;
import com.promptoven.authservice.application.port.in.usecase.ChangePWUseCase;
import com.promptoven.authservice.application.port.in.usecase.EmailCheckUseCase;
import com.promptoven.authservice.application.port.in.usecase.EmailRequestUseCase;
import com.promptoven.authservice.application.port.in.usecase.LoginUseCase;
import com.promptoven.authservice.application.port.in.usecase.LogoutUseCase;
import com.promptoven.authservice.application.port.in.usecase.OauthLoginUseCase;
import com.promptoven.authservice.application.port.in.usecase.OauthRegisterUseCase;
import com.promptoven.authservice.application.port.in.usecase.OauthUnregisterUseCase;
import com.promptoven.authservice.application.port.in.usecase.RegisterFromSocialLoginUseCase;
import com.promptoven.authservice.application.port.in.usecase.RegisterUseCase;
import com.promptoven.authservice.application.port.in.usecase.ResetPWUseCase;
import com.promptoven.authservice.application.port.in.usecase.VerifyEmailUseCase;
import com.promptoven.authservice.application.port.in.usecase.VerifyNicknameUseCase;
import com.promptoven.authservice.application.port.in.usecase.WithdrawUseCase;
import com.promptoven.authservice.application.port.out.dto.LoginDTO;
import com.promptoven.authservice.application.port.out.dto.SocialLoginDTO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/auth")
public class AuthRestController {

	private final ChangePWUseCase changePWUseCase;
	private final EmailCheckUseCase emailCheckUseCase;
	private final EmailRequestUseCase emailRequestUseCase;
	private final LoginUseCase loginUseCase;
	private final OauthLoginUseCase oauthLoginUseCase;
	private final OauthRegisterUseCase oauthRegisterUseCase;
	private final OauthUnregisterUseCase oauthUnregisterUseCase;
	private final RegisterFromSocialLoginUseCase registerFromSocialLoginUseCase;
	private final RegisterUseCase registerUseCase;
	private final ResetPWUseCase resetPWUseCase;
	private final VerifyEmailUseCase verifyEmailUseCase;
	private final VerifyNicknameUseCase verifyNicknameUseCase;
	private final LogoutUseCase logoutUseCase;
	private final WithdrawUseCase withdrawUseCase;

	@PostMapping("/login")
	public LoginResponseVO login(@RequestBody LoginRequestVO loginRequestVO) {
		LoginDTO loginDTO = loginUseCase.login(loginRequestVO.getEmail(), loginRequestVO.getPassword());
		return LoginResponseVO.from(loginDTO);
	}

	@PostMapping("/oauth/login")
	public SocialLoginResponseVO oauthLogin(@RequestBody OauthLoginRequestVO oauthLoginRequestVO) {
		SocialLoginDTO socialLoginDTO = oauthLoginUseCase.oauthLogin(
			oauthLoginRequestVO.getProvider(), oauthLoginRequestVO.getProviderID(), oauthLoginRequestVO.getEmail());
		return SocialLoginResponseVO.from(socialLoginDTO);
		// todo: 만약에 false가 들어가있고 나머지가 들어가 null 이면 register-social로 가야합니다. @Frontend Dev : 302 redirect하기
	}

	@PostMapping("/logout")
	public void logout(@RequestHeader("Authorization") String authorizationHeader,
		@RequestHeader("RefreshToken") String refreshTokenHeader) {
		String accessToken = authorizationHeader.replace("Bearer ", "");
		String refreshToken = refreshTokenHeader.replace("Bearer ", "");
		logoutUseCase.logout(accessToken, refreshToken);
	}

	@PostMapping("/register")
	public LoginResponseVO register(@RequestBody RegisterRequestVO registerRequestVO) {
		LoginDTO loginDTO = registerUseCase.register(registerRequestVO.getEmail(), registerRequestVO.getPassword(),
			registerRequestVO.getNickname());
		return LoginResponseVO.from(loginDTO);
	}

	@PostMapping("/oauth/register")
	public void oauthRegister(@RequestBody OauthRegisterRequestVO oauthRegisterRequestVO) {
		oauthRegisterUseCase.OauthRegister(oauthRegisterRequestVO.getProvider(), oauthRegisterRequestVO.getProviderId(),
			oauthRegisterRequestVO.getMemberUUID());
	}

	@PostMapping("/oauth/unregister")
	public void oauthUnregister(@RequestBody OauthUnregisterRequestVO oauthUnregisterRequestVO) {
		oauthUnregisterUseCase.OauthUnregister(oauthUnregisterRequestVO.getProvider(),
			oauthUnregisterRequestVO.getProviderId(), oauthUnregisterRequestVO.getMemberUUID());
	}

	@PostMapping("/withdraw")
	public void withdraw(@RequestHeader("Authorization") String authorizationHeader) {
		String accessToken = authorizationHeader.replace("Bearer ", "");
		withdrawUseCase.withdraw(accessToken);
	}

	@PostMapping("/resetPW")
	public void resetPW(@RequestBody ResetPWRequestVO resetPWRequestVO) {
		resetPWUseCase.resetPW(resetPWRequestVO.getEmail(), resetPWRequestVO.getPassword());
	}

	@PostMapping("/changePW")
	public boolean changePW(@RequestBody ChangePWRequestVO changePWRequestVO) {
		return changePWUseCase.changePW(changePWRequestVO.getPassword(), changePWRequestVO.getNewPassword(),
			changePWRequestVO.getMemberUUID());
	}

	@PostMapping("/email/reqeust")
	public void emailRequest(@RequestBody EmailRequestRequestVO emailRequestRequestVO) {
		log.info("email request: {}", emailRequestRequestVO);
		emailRequestUseCase.requestEmail(emailRequestRequestVO.getEmail());
	}

	@PostMapping("/email/check")
	public boolean emailCheck(@RequestBody EmailCheckRequestVO emailCheckRequestVO) {
		log.info("email check: {}", emailCheckRequestVO);
		return emailCheckUseCase.checkMedia(emailCheckRequestVO.getEmail(), emailCheckRequestVO.getCode());
	}

	@PostMapping("/verify/email")
	public boolean verifyEmail(@RequestBody VerifyEmailRequestVO verifyEmailRequestVO) {
		log.info("verify email: {}", verifyEmailRequestVO);
		return verifyEmailUseCase.verifyEmail(verifyEmailRequestVO.getEmail());
	}

	@PostMapping("/verify/nickname")
	public boolean verifyNickname(@RequestBody VerifyNicknameRequestVO verifyNicknameRequestVO) {
		log.info("verify nickname: {}", verifyNicknameRequestVO);
		return verifyNicknameUseCase.verifyNickname(verifyNicknameRequestVO.getNickname());
	}

	@PostMapping("/register-social")
	public LoginResponseVO registerSocial(@RequestBody RegisterSocialRequestVO registerSocialRequestVO) {
		log.info("register social: {}", registerSocialRequestVO);
		return LoginResponseVO.from(
			registerFromSocialLoginUseCase.registerFromSocialLogin(registerSocialRequestVO.getEmail(),
				registerSocialRequestVO.getNickname(), registerSocialRequestVO.getPassword(),
				registerSocialRequestVO.getProvider(),
				registerSocialRequestVO.getProviderId()));
	}
}
