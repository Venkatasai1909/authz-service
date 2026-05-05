package com.venkatasai.auth.authz_service.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthContext {
    private final String userId;
    private final String action;
    private final String path;
}