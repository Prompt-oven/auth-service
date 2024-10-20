package com.promptoven.authservice.application.service;

import org.springframework.stereotype.Service;

import com.promptoven.authservice.application.port.in.usecase.MemberUseCases;
import com.promptoven.authservice.application.port.out.call.MemberPersistence;
import com.promptoven.authservice.application.port.out.call.RolePersistence;
import com.promptoven.authservice.domain.Member;
import com.promptoven.authservice.domain.Role;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberUseCases {
	private final MemberPersistence memberPersistence;
	private final RolePersistence rolePersistence;

	@Override
	public void promoteToSeller(String memberUUID) {
		Member member = memberPersistence.findByUuid(memberUUID);
		memberPersistence.updateMember(Member.updateMemberRole(member, 2));
	}

	@Override
	public void setMemberRole(String memberUUID, String roleName) {
		Role role = rolePersistence.findByName(roleName);
		Member member = memberPersistence.findByUuid(memberUUID);
		memberPersistence.updateMember(Member.updateMemberRole(member, role.getId()));
	}

	@Override
	public void banMember(String memberUUID) {
		Member member = memberPersistence.findByUuid(memberUUID);
		memberPersistence.updateMember(Member.banMember(member));
	}

	@Override
	public void unbanMember(String memberUUID) {
		Member member = memberPersistence.findByUuid(memberUUID);
		memberPersistence.updateMember(Member.unbanMember(member));
	}

	@Override
	public void updateNickname(String memberUUID, String nickname) {
		Member member = memberPersistence.findByUuid(memberUUID);
		memberPersistence.updateMember(Member.updateMemberNickname(member, nickname));
	}
}
