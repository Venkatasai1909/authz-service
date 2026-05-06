package com.venkatasai.auth.authz_service.caching;

import com.venkatasai.auth.authz_service.config.CacheConfig;
import com.venkatasai.auth.authz_service.model.User;
import com.venkatasai.auth.authz_service.repository.UserRepository;
import com.venkatasai.auth.authz_service.repository.impl.JdbcUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cache.CacheManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {CacheConfig.class, JdbcUserRepository.class})
class UserCacheTest {

    @MockBean
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CacheManager cacheManager;

    private final User user123 = User.builder()
            .id(1).userId("user123").externalUserId("ext-user123").build();

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        cacheManager.getCache("users").clear();
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("ext-user123")))
                .thenReturn(List.of(user123));
    }

    // ── findByExternalUserId: cache hit ───────────────────────────────────────

    @Test
    @DisplayName("Second call with same externalUserId returns cached result — DB not queried again")
    @SuppressWarnings("unchecked")
    void sameExternalUserId_secondCallHitsCache_dbCalledOnce() {
        Optional<User> first  = userRepository.findByExternalUserId("ext-user123");
        Optional<User> second = userRepository.findByExternalUserId("ext-user123");

        assertThat(first).isEqualTo(second);
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("ext-user123"));
    }

    @Test
    @DisplayName("Cached user result is the same object reference on cache hit")
    @SuppressWarnings("unchecked")
    void cacheHit_returnsSameReference() {
        Optional<User> first  = userRepository.findByExternalUserId("ext-user123");
        Optional<User> second = userRepository.findByExternalUserId("ext-user123");

        assertThat(first).isSameAs(second);
    }

    @Test
    @DisplayName("N repeated calls with same externalUserId result in exactly 1 DB query")
    @SuppressWarnings("unchecked")
    void repeatedCalls_onlyOneDbQuery() {
        for (int i = 0; i < 10; i++) {
            userRepository.findByExternalUserId("ext-user123");
        }

        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("ext-user123"));
    }

    // ── findByExternalUserId: cache miss ──────────────────────────────────────

    @Test
    @DisplayName("Different externalUserId produces a cache miss — DB queried separately for each")
    @SuppressWarnings("unchecked")
    void differentExternalUserId_separateCacheEntries_dbCalledForEach() {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("ext-user456")))
                .thenReturn(List.of());

        userRepository.findByExternalUserId("ext-user123");
        userRepository.findByExternalUserId("ext-user456");

        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("ext-user123"));
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("ext-user456"));
    }

    @Test
    @DisplayName("Empty result (unknown externalUserId) is also cached — DB not re-queried")
    @SuppressWarnings("unchecked")
    void unknownExternalUserId_emptyResultCached_dbCalledOnce() {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("ext-unknown")))
                .thenReturn(List.of());

        Optional<User> first  = userRepository.findByExternalUserId("ext-unknown");
        Optional<User> second = userRepository.findByExternalUserId("ext-unknown");

        assertThat(first).isEmpty();
        assertThat(second).isEmpty();
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("ext-unknown"));
    }

    // ── findByUserIdAndExternalUserId: cache hit ──────────────────────────────

    @Test
    @DisplayName("Second call with same composite key returns cached result — DB not queried again")
    @SuppressWarnings("unchecked")
    void sameCompositeKey_secondCallHitsCache_dbCalledOnce() {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("user123"), eq("ext-user123")))
                .thenReturn(List.of(user123));

        Optional<User> first  = userRepository.findByUserIdAndExternalUserId("user123", "ext-user123");
        Optional<User> second = userRepository.findByUserIdAndExternalUserId("user123", "ext-user123");

        assertThat(first).isEqualTo(second);
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user123"), eq("ext-user123"));
    }

    @Test
    @DisplayName("Different composite key produces a cache miss — DB queried separately for each")
    @SuppressWarnings("unchecked")
    void differentCompositeKey_separateCacheEntries_dbCalledForEach() {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("user123"), eq("ext-user123")))
                .thenReturn(List.of(user123));
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("user456"), eq("ext-user456")))
                .thenReturn(List.of());

        userRepository.findByUserIdAndExternalUserId("user123", "ext-user123");
        userRepository.findByUserIdAndExternalUserId("user456", "ext-user456");

        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user123"), eq("ext-user123"));
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user456"), eq("ext-user456"));
    }

    // ── Cache key isolation ───────────────────────────────────────────────────

    @Test
    @DisplayName("findByExternalUserId and findByUserIdAndExternalUserId use independent cache keys — no cross-hit")
    @SuppressWarnings("unchecked")
    void twoMethods_independentCacheKeys_noCrossHit() {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("user123"), eq("ext-user123")))
                .thenReturn(List.of(user123));

        // Populate cache for findByExternalUserId
        userRepository.findByExternalUserId("ext-user123");
        // Call findByUserIdAndExternalUserId — must NOT hit the externalUserId-only cache entry
        userRepository.findByUserIdAndExternalUserId("user123", "ext-user123");

        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("ext-user123"));
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user123"), eq("ext-user123"));
    }
}