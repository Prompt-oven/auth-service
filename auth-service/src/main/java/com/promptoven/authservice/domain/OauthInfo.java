package com.promptoven.authservice.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Builder
public class OauthInfo {

    private Long id;
    private String provider;
    private String providerID;
    private String memberUUID;

    public static OauthInfo createOauthInfo(
            Long id, String provider,
            String providerID, String memberUUID)
    {
        return OauthInfo.builder()
                .id(id)
                .provider(provider)
                .providerID(providerID)
                .memberUUID(memberUUID)
                .build();
    }
}
