package com.venkatasai.auth.authz_service.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class DecodedToken {
    private String subject;
    private String issuer;
    private Instant expiry;
    private Map<String, Object> claims;
}
