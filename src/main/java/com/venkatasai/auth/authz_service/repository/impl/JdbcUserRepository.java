package com.venkatasai.auth.authz_service.repository.impl;

import com.venkatasai.auth.authz_service.model.User;
import com.venkatasai.auth.authz_service.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Slf4j
@Repository
@AllArgsConstructor
public class JdbcUserRepository implements UserRepository {

    private final JdbcTemplate jdbcTemplate;

    private static final String FIND_BY_EXTERNAL_USER_ID =
            "SELECT id, user_id, external_user_id " +
                    "FROM users " +
                    "WHERE external_user_id = ?";

    private static final String FIND_BY_USER_ID_AND_EXTERNAL_USER_ID =
            "SELECT id, user_id, external_user_id " +
                    "FROM users " +
                    "WHERE user_id = ? AND external_user_id = ?";

    private final RowMapper<User> userRowMapper = (rs, rowNum) ->
            User.builder()
                    .id(rs.getInt("id"))
                    .userId(rs.getString("user_id"))
                    .externalUserId(rs.getString("external_user_id"))
                    .build();

    @Override
    @Cacheable(value = "users", key = "#externalUserId")
    public Optional<User> findByExternalUserId(String externalUserId) {
        log.debug("Querying user by externalUserId={}", externalUserId);
        try {
            List<User> results = jdbcTemplate.query(
                    FIND_BY_EXTERNAL_USER_ID,
                    userRowMapper,
                    externalUserId
            );

            return results.stream().findFirst();
        } catch (Exception e) {
            log.error("DB error fetching user for externalUserId={}", externalUserId, e);
            throw e;
        }
    }

    @Override
    @Cacheable(value = "users", key = "#userId + '|' + #externalUserId")
    public Optional<User> findByUserIdAndExternalUserId(String userId, String externalUserId) {
        log.debug("Querying user by userId={} externalUserId={}", userId, externalUserId);
        try {
            List<User> results = jdbcTemplate.query(
                    FIND_BY_USER_ID_AND_EXTERNAL_USER_ID,
                    userRowMapper,
                    userId,
                    externalUserId
            );

            return results.stream().findFirst();
        } catch (Exception e) {
            log.error("DB error fetching user for userId={} externalUserId={}", userId, externalUserId, e);
            throw e;
        }
    }
}