package com.venkatasai.auth.authz_service.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserPrincipal {
    private final String userId;
    private final String email;
}
