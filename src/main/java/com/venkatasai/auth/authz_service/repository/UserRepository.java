package com.venkatasai.auth.authz_service.repository;

import com.venkatasai.auth.authz_service.model.User;

import java.util.Optional;

public interface UserRepository {
    Optional<User> findByExternalUserId(String externalUserId);
    Optional<User> findByUserIdAndExternalUserId(String userId, String externalUserId);
}
