package com.promptoven.authservice.adaptor.jpa.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@Table(name = "sociallogininfo", indexes = {
	@Index(name = "idx_uuid", columnList = "memberUUID")
})
@NoArgsConstructor
@AllArgsConstructor
public class SocialLoginInfoEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String memberUUID;
	private String provider;
	private String providerID;

}
