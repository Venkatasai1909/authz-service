package com.venkatasai.auth.authz_service.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {
    private Integer id;
    private String userId;
    private String externalUserId;
}
