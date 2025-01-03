package com.promptoven.authservice.adaptor.web.controller;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.promptoven.authservice.adaptor.web.controller.mapper.reqeust.SocialLoginAssociateRequestMapper;
import com.promptoven.authservice.adaptor.web.controller.mapper.reqeust.SocialLoginDisassociateRequestMapper;
import com.promptoven.authservice.adaptor.web.controller.mapper.reqeust.SocialLoginRequestMapper;
import com.promptoven.authservice.adaptor.web.controller.mapper.response.SocialLoginInfoResponseMapper;
import com.promptoven.authservice.adaptor.web.controller.mapper.response.SocialLoginResponseMapper;
import com.promptoven.authservice.adaptor.web.controller.vo.in.SocialLoginAssociateRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.SocialLoginDisassociateRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.SocialLoginRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.out.SocialLoginInfoResponseVO;
import com.promptoven.authservice.adaptor.web.controller.vo.out.SocialLoginResponseVO;
import com.promptoven.authservice.application.port.in.usecase.SocialLoginUseCase;
import com.promptoven.authservice.application.port.out.dto.SocialLoginDTO;
import com.promptoven.authservice.adaptor.web.util.BaseResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/auth/social")
public class SocialLoginRestController {

	private final SocialLoginUseCase socialLoginUseCase;

	@PostMapping("/login")
	public BaseResponse<SocialLoginResponseVO> socialLogin(
		@RequestBody SocialLoginRequestVO socialLoginRequestVO) {
		SocialLoginDTO socialLoginDTO = socialLoginUseCase.SocialLogin(
			SocialLoginRequestMapper.toDTO(socialLoginRequestVO));
		return new BaseResponse<>(SocialLoginResponseMapper.fromDTO(socialLoginDTO));
	}

	@PostMapping("/info")
	public BaseResponse<Void> socialLoginAssociate(
		@RequestBody SocialLoginAssociateRequestVO socialLoginAssociateRequestVO) {
		socialLoginUseCase.SocialLoginAssociate(SocialLoginAssociateRequestMapper.toDTO(socialLoginAssociateRequestVO));
		return new BaseResponse<>();
	}

	@DeleteMapping("/info")
	public BaseResponse<Void> socialLoginDisassociate(
		@RequestBody SocialLoginDisassociateRequestVO socialLoginDisassociateRequestVO) {
		socialLoginUseCase.SocialLoginDisassociate(
			SocialLoginDisassociateRequestMapper.toDTO(socialLoginDisassociateRequestVO));
		return new BaseResponse<>();
	}

	@GetMapping("/info")
	public BaseResponse<List<SocialLoginInfoResponseVO>> getSocialLoginAssociations(
		@RequestHeader("Authorization") String accessToken) {
		List<SocialLoginInfoResponseVO> result = socialLoginUseCase.getSocialLoginAssociations(accessToken).stream()
			.map(SocialLoginInfoResponseMapper::fromDTO)
			.collect(Collectors.toList());
		return new BaseResponse<>(result);
	}

}
