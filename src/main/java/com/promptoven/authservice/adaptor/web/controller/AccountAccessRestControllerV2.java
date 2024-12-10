package com.promptoven.authservice.adaptor.web.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.promptoven.authservice.adaptor.web.controller.mapper.reqeust.LoginRequestMapper;
import com.promptoven.authservice.adaptor.web.controller.mapper.response.LoginResponseMapper;
import com.promptoven.authservice.adaptor.web.controller.vo.in.LoginRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.out.LoginResponseVO;
import com.promptoven.authservice.adaptor.web.util.BaseResponse;
import com.promptoven.authservice.adaptor.web.util.BaseResponseStatus;
import com.promptoven.authservice.application.port.in.DHkeyExchangeUsecase;
import com.promptoven.authservice.application.port.in.usecase.AccountAccessUsecase;
import com.promptoven.authservice.application.port.out.dto.LoginResponseDTO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v2/auth")
public class AccountAccessRestControllerV2 {

	private final AccountAccessUsecase accountAccessUsecase;
	private final DHkeyExchangeUsecase dHkeyExchangeUsecase;

	@PostMapping("/login")
	public BaseResponse<LoginResponseVO> login(@RequestBody LoginRequestVO loginRequestVO,
		@RequestHeader("X-Session-ID") String sessionId) {
		String encryptedPassword = loginRequestVO.getPassword();
		try {
			String decryptedPassword = dHkeyExchangeUsecase.decryptPassword(sessionId, encryptedPassword);
			LoginRequestVO decryptedPWLoginRequestVO = new LoginRequestVO(loginRequestVO.getEmail(),
				decryptedPassword);
			LoginResponseDTO loginResponseDTO = accountAccessUsecase.login(
				LoginRequestMapper.toDTO(decryptedPWLoginRequestVO));
			if (loginResponseDTO == null) {
				return new BaseResponse<>(BaseResponseStatus.FAILED_LOGIN);
			}
			return new BaseResponse<>(LoginResponseMapper.fromDTO(loginResponseDTO));
		} catch (Exception e) {
			e.printStackTrace();
			return new BaseResponse<>(BaseResponseStatus.INTERNAL_SERVER_ERROR);
		}
	}
}
