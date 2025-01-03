package com.promptoven.authservice.application.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.promptoven.authservice.adaptor.web.util.BaseException;
import com.promptoven.authservice.adaptor.web.util.BaseResponseStatus;
import com.promptoven.authservice.application.port.in.dto.ChangePWRequestDTO;
import com.promptoven.authservice.application.port.in.dto.ResetPWRequestDTO;
import com.promptoven.authservice.application.port.in.dto.SetMemberRoleRequestDTO;
import com.promptoven.authservice.application.port.in.dto.UpdateNicknameRequestDTO;
import com.promptoven.authservice.application.port.in.usecase.MemberManagementUseCase;
import com.promptoven.authservice.application.port.out.call.EventPublisher;
import com.promptoven.authservice.application.port.out.call.MemberPersistence;
import com.promptoven.authservice.application.port.out.call.RolePersistence;
import com.promptoven.authservice.application.port.out.dto.MemberBanEvent;
import com.promptoven.authservice.application.port.out.dto.MemberNicknameUpdateEvent;
import com.promptoven.authservice.application.port.out.dto.MemberUnbanEvent;
import com.promptoven.authservice.application.service.dto.MemberDTO;
import com.promptoven.authservice.application.service.dto.mapper.MemberDomainDTOMapper;
import com.promptoven.authservice.application.service.dto.mapper.RoleDomainDTOMapper;
import com.promptoven.authservice.domain.Member;
import com.promptoven.authservice.domain.Role;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberManagementService implements MemberManagementUseCase {

	private final MemberPersistence memberPersistence;
	private final RolePersistence rolePersistence;
	private final EventPublisher eventPublisher;
	private final PasswordEncoder passwordEncoder;
	private final RoleDomainDTOMapper roleDomainDTOMapper;
	private final MemberDomainDTOMapper memberDomainDTOMapper;

	@Value("${member-ban-event}")
	private String memberBannedTopic;
	@Value("${member-unban-event}")
	private String memberUnbanTopic;
	@Value("${member-nickname-update-event}")
	private String memberNicknameUpdatedTopic;

	@Override
	public void promoteToSeller(Member member) {
		memberPersistence.updateMember(memberDomainDTOMapper.toDTO(Member.updateMemberRole(member, 2)));
	}

	@Override
	public void setMemberRole(Member member, SetMemberRoleRequestDTO setMemberRoleRequestDTO) {
		Role role = roleDomainDTOMapper.toDomain(rolePersistence.findByName(setMemberRoleRequestDTO.getRoleName()));
		memberPersistence.updateMember(memberDomainDTOMapper.toDTO(Member.updateMemberRole(member, role.getId())));
	}

	@Override
	public void banMember(Member member) {
		eventPublisher.publish(memberBannedTopic, new MemberBanEvent(member.getUuid()));
		memberPersistence.updateMember(memberDomainDTOMapper.toDTO(Member.banMember(member)));
	}

	@Override
	public void unbanMember(Member member) {
		eventPublisher.publish(memberUnbanTopic, new MemberUnbanEvent(member.getUuid()));
		memberPersistence.updateMember(memberDomainDTOMapper.toDTO(Member.unbanMember(member)));
	}

	@Override
	public void updateNickname(Member member, UpdateNicknameRequestDTO updateNicknameRequestDTO) {
		String nickname = updateNicknameRequestDTO.getNickname();
		memberPersistence.updateMember(memberDomainDTOMapper.toDTO(Member.updateMemberNickname(member, nickname)));
		eventPublisher.publish(
			memberNicknameUpdatedTopic,
			MemberNicknameUpdateEvent.builder()
				.memberUUID(member.getUuid())
				.nickname(nickname)
				.build()
		);
	}

	@Override
	public void clearPassword(Member member) {
		memberPersistence.updateMember(memberDomainDTOMapper.toDTO(Member.updateMemberPassword(member, "clear")));
	}

	@Override
	public void changePW(ChangePWRequestDTO changePWRequestDTO) {

		MemberDTO memberDTO = memberPersistence.findByUuid(changePWRequestDTO.getMemberUUID());
		Member member = memberDomainDTOMapper.toDomain(memberDTO);
		String newPassword = changePWRequestDTO.getNewPassword();
		Member updatedMember = Member.updateMemberPassword(member, passwordEncoder.encode(newPassword));
		MemberDTO updatedMemberDTO = memberDomainDTOMapper.toDTO(updatedMember);
		memberPersistence.updatePassword(updatedMemberDTO);
	}

	@Override
	public void resetPW(ResetPWRequestDTO resetPWRequestDTO) {

		MemberDTO memberDTO = memberPersistence.findByEmail(resetPWRequestDTO.getEmail());
		if (memberDTO == null) {
			throw new BaseException(BaseResponseStatus.NOT_FOUND_DATA);
		}
		Member member = memberDomainDTOMapper.toDomain(memberDTO);
		MemberDTO updatedMemberDTO = memberDomainDTOMapper.toDTO(
			Member.updateMemberPassword(member, passwordEncoder.encode(resetPWRequestDTO.getPassword())));
		memberPersistence.updatePassword(updatedMemberDTO);
	}
}