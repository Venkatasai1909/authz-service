package com.venkatasai.auth.authz_service.policy.matcher;

public interface ResourceMatcher {
    boolean matches(String resource, String path);
}
