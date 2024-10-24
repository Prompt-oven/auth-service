package com.promptoven.authservice.application.port.out.call;

import com.promptoven.authservice.domain.Member;

public interface MemberPersistence {

	void create(Member member);

	Member findByEmail(String email);

	Member findByUuid(String uuid);

	Member findByNickname(String nickname);

	boolean existsByEmail(String email);

	boolean existsByNickname(String nickname);

	void updatePassword(Member updatedMember);

	void remove(Member member);

	void updateMember(Member updatedMember);

}
