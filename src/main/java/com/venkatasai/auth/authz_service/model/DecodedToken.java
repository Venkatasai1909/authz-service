package com.venkatasai.auth.authz_service.model;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Getter
@Builder
public class DecodedToken {
    private final String subject;
    private final String issuer;
    private final Instant expiry;
    private final Instant notBefore;
    private final List<String> audience;
    private final Map<String, Object> claims;
}