package com.venkatasai.auth.authz_service.policy.scorer;

public interface Scorer {
    int calculateScore(String resource, String path);
}
