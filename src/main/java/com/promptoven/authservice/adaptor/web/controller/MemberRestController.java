package com.promptoven.authservice.adaptor.web.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.promptoven.authservice.adaptor.web.controller.mapper.reqeust.ChangePWRequestMapper;
import com.promptoven.authservice.adaptor.web.controller.mapper.reqeust.UpdateNicknameRequestMapper;
import com.promptoven.authservice.adaptor.web.controller.vo.in.ChangePWRequestVO;
import com.promptoven.authservice.adaptor.web.controller.vo.in.UpdateNicknameRequestVO;
import com.promptoven.authservice.application.service.aop.MemberManagementProxy;
import com.promptoven.authservice.adaptor.web.util.BaseResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/member/auth")
public class MemberRestController {

	private final MemberManagementProxy memberManagementProxy;

	@PutMapping("/nickname")
	public BaseResponse<Void> updateNickname(@RequestBody UpdateNicknameRequestVO updateNicknameRequestVO) {
		memberManagementProxy.updateNickname(UpdateNicknameRequestMapper.toDTO(updateNicknameRequestVO));
		return new BaseResponse<>();
	}

	@PostMapping("/changePW")
	public BaseResponse<Void> changePW(@RequestBody ChangePWRequestVO changePWRequestVO) {
		memberManagementProxy.changePW(ChangePWRequestMapper.toDTO(changePWRequestVO));
		return new BaseResponse<>();
	}
}