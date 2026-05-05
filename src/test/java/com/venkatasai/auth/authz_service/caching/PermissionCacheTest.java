package com.venkatasai.auth.authz_service.caching;

import com.venkatasai.auth.authz_service.config.CacheConfig;
import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.repository.PermissionRepository;
import com.venkatasai.auth.authz_service.repository.impl.JdbcPermissionRepository;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {CacheConfig.class, JdbcPermissionRepository.class})
class PermissionCacheTest {

    @MockBean
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private CacheManager cacheManager;

    private final List<Permission> readPermissions = List.of(
            Permission.builder().id(1).userId("user123").action("read").resource("transactions").effect("allow").build()
    );

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        cacheManager.getCache("permissions").clear();
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("user123"), eq("read")))
                .thenReturn(readPermissions);
    }

    // ── Cache hit ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Second call with same key returns cached result — DB not queried again")
    @SuppressWarnings("unchecked")
    void sameKey_secondCallHitsCache_dbCalledOnce() {
        List<Permission> first  = permissionRepository.findByUserIdAndAction("user123", "read");
        List<Permission> second = permissionRepository.findByUserIdAndAction("user123", "read");

        assertThat(first).isEqualTo(second);
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user123"), eq("read"));
    }

    @Test
    @DisplayName("Cached result is the same object reference on cache hit")
    @SuppressWarnings("unchecked")
    void cacheHit_returnsSameReference() {
        List<Permission> first  = permissionRepository.findByUserIdAndAction("user123", "read");
        List<Permission> second = permissionRepository.findByUserIdAndAction("user123", "read");

        assertThat(first).isSameAs(second);
    }

    // ── Cache miss: different keys ─────────────────────────────────────────────

    @Test
    @DisplayName("Different userId produces a cache miss — DB queried separately for each user")
    @SuppressWarnings("unchecked")
    void differentUserId_separateCacheEntries_dbCalledForEach() {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("user456"), eq("read")))
                .thenReturn(List.of());

        permissionRepository.findByUserIdAndAction("user123", "read");
        permissionRepository.findByUserIdAndAction("user456", "read");

        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user123"), eq("read"));
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user456"), eq("read"));
    }

    @Test
    @DisplayName("Different action produces a cache miss — DB queried separately for each action")
    @SuppressWarnings("unchecked")
    void differentAction_separateCacheEntries_dbCalledForEach() {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("user123"), eq("write")))
                .thenReturn(List.of());

        permissionRepository.findByUserIdAndAction("user123", "read");
        permissionRepository.findByUserIdAndAction("user123", "write");

        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user123"), eq("read"));
        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user123"), eq("write"));
    }

    // ── Multiple repeated calls ───────────────────────────────────────────────

    @Test
    @DisplayName("N repeated calls with same key result in exactly 1 DB query")
    @SuppressWarnings("unchecked")
    void repeatedCalls_onlyOneDbQuery() {
        for (int i = 0; i < 10; i++) {
            permissionRepository.findByUserIdAndAction("user123", "read");
        }

        verify(jdbcTemplate, times(1)).query(anyString(), any(RowMapper.class), eq("user123"), eq("read"));
    }
}