package com.promptoven.authservice.adaptor.web.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.promptoven.authservice.adaptor.web.controller.vo.in.EmailCheckRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.EmailRequestRequestVO;
import com.promptoven.authservice.application.port.in.usecase.MediaAuthUseCase;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/auth")
public class MediaAuthRestController {

	private final MediaAuthUseCase mediaAuthUseCase;

	@PostMapping("/email/request")
	public void emailRequest(@RequestBody EmailRequestRequestVO emailRequestRequestVO) {
		log.info("email request: {}", emailRequestRequestVO);
		mediaAuthUseCase.requestEmail(emailRequestRequestVO.getEmail());
	}

	@PostMapping("/email/check")
	public boolean emailCheck(@RequestBody EmailCheckRequestVO emailCheckRequestVO) {
		log.info("email check: {}", emailCheckRequestVO);
		return mediaAuthUseCase.checkMedia(emailCheckRequestVO.getEmail(), emailCheckRequestVO.getCode());
	}

}