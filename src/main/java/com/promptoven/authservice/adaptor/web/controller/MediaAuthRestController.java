package com.promptoven.authservice.adaptor.web.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.promptoven.authservice.adaptor.web.controller.mapper.reqeust.EmailCheckRequestMapper;
import com.promptoven.authservice.adaptor.web.controller.mapper.reqeust.EmailRequestRequestMapper;
import com.promptoven.authservice.adaptor.web.controller.vo.in.EmailCheckRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.EmailRequestRequestVO;
import com.promptoven.authservice.application.port.in.usecase.VerificationUseCase;
import com.promptoven.authservice.adaptor.web.util.BaseResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/auth")
public class MediaAuthRestController {

	private final VerificationUseCase verificationUseCase;

	@PostMapping("/email/request")
	public BaseResponse<Void> emailRequest(@RequestBody EmailRequestRequestVO emailRequestRequestVO) {
		verificationUseCase.requestEmail(EmailRequestRequestMapper.toDTO(emailRequestRequestVO));
		return new BaseResponse<>();
	}

	@PostMapping("/email/check")
	public BaseResponse<Boolean> emailCheck(@RequestBody EmailCheckRequestVO emailCheckRequestVO) {
		return new BaseResponse<>(verificationUseCase.checkMedia(EmailCheckRequestMapper.toDTO(emailCheckRequestVO)));
	}

}
