package com.promptoven.authservice.adaptor.infrastructure.jpa.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.promptoven.authservice.adaptor.infrastructure.jpa.entity.MemberEntity;

public interface MemberRepository extends JpaRepository<MemberEntity, Long> {
	MemberEntity findByEmail(String email);

	MemberEntity findByUuid(String uuid);

	boolean existsByEmail(String email);

	boolean existsByNickname(String nickname);
}
