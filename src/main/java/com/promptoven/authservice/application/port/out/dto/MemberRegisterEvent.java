package com.promptoven.authservice.application.port.out.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Builder
@AllArgsConstructor
@Getter
public class MemberRegisterEvent {

	private final String memberUUID;
	private final String nickname;
}