package com.venkatasai.auth.authz_service.service;

import com.venkatasai.auth.authz_service.authentication.JwtAuthenticator;
import com.venkatasai.auth.authz_service.mapper.AuthorizationMapper;
import com.venkatasai.auth.authz_service.authorization.AuthorizationManager;
import com.venkatasai.auth.authz_service.authorization.factory.AuthorizationFactory;
import com.venkatasai.auth.authz_service.authorization.strategy.PolicyEngineStrategy;
import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.dto.response.AuthorizationResponse;
import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.model.*;
import com.venkatasai.auth.authz_service.policy.engine.PolicyEngine;
import com.venkatasai.auth.authz_service.policy.matcher.DefaultResourceMatcher;
import com.venkatasai.auth.authz_service.policy.resolver.DenyOverridesResolver;
import com.venkatasai.auth.authz_service.policy.scorer.SpecificityScorer;
import com.venkatasai.auth.authz_service.repository.PermissionRepository;
import com.venkatasai.auth.authz_service.service.impl.AuthorizationServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceImplTest {

    @Mock
    private JwtAuthenticator jwtAuthenticator;

    @Mock
    private PermissionRepository permissionRepository;

    private AuthorizationServiceImpl service;

    @BeforeEach
    void setUp() {
        // Wire real engine components; only mock JWT and DB
        PolicyEngine policyEngine = new PolicyEngine(
                new DefaultResourceMatcher(),
                new SpecificityScorer(),
                new DenyOverridesResolver()
        );
        PolicyEngineStrategy strategy = new PolicyEngineStrategy(policyEngine);
        AuthorizationFactory factory = new AuthorizationFactory(List.of(strategy));
        AuthorizationManager manager = new AuthorizationManager(factory);

        service = new AuthorizationServiceImpl(jwtAuthenticator, permissionRepository, manager, new AuthorizationMapper());
    }

    private UserPrincipal principal(String userId) {
        return UserPrincipal.builder().userId(userId).build();
    }

    private Permission allow(String userId, String action, String resource) {
        return Permission.builder().id(1).userId(userId).action(action).resource(resource).effect("allow").build();
    }

    private Permission deny(String userId, String action, String resource) {
        return Permission.builder().id(2).userId(userId).action(action).resource(resource).effect("deny").build();
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("Valid token + matching allow permission → ALLOW response")
    void validToken_allowPermission_returnsAllow() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("user123"));
        when(permissionRepository.findByUserIdAndAction("user123", "read"))
                .thenReturn(List.of(allow("user123", "read", "transactions")));

        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "GET", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        assertThat(response.getUserId()).isEqualTo("user123");
        assertThat(response.getReason()).contains("granted");
        assertThat(response.getMatchedPermissions()).hasSize(1);
    }

    @Test
    @DisplayName("Valid token + explicit deny rule → DENY response")
    void validToken_denyPermission_returnsDeny() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("user123"));
        when(permissionRepository.findByUserIdAndAction("user123", "delete"))
                .thenReturn(List.of(deny("user123", "delete", "transactions")));

        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "DELETE", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        assertThat(response.getUserId()).isEqualTo("user123");
        assertThat(response.getReason()).contains("denied");
    }

    @Test
    @DisplayName("Valid token + no matching permissions → DENY (default deny)")
    void validToken_noPermissions_returnsDeny() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("user456"));
        when(permissionRepository.findByUserIdAndAction("user456", "write"))
                .thenReturn(List.of()); // no write permissions

        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "POST", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        assertThat(response.getReason()).contains("No matching permission");
        assertThat(response.getMatchedPermissions()).isEmpty();
    }

    // ── Action mapping ────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST method maps to 'write' action for DB query")
    void postMethod_queriesWithWriteAction() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("u"));
        when(permissionRepository.findByUserIdAndAction("u", "write"))
                .thenReturn(List.of());

        service.authorize(new AuthorizationRequest("tok", "POST", "/transactions"));

        // Must query with "write", not "POST"
        verify(permissionRepository).findByUserIdAndAction("u", "write");
        verify(permissionRepository, never()).findByUserIdAndAction(anyString(), eq("POST"));
    }

    @Test
    @DisplayName("DELETE method maps to 'delete' action for DB query")
    void deleteMethod_queriesWithDeleteAction() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("u"));
        when(permissionRepository.findByUserIdAndAction("u", "delete"))
                .thenReturn(List.of());

        service.authorize(new AuthorizationRequest("tok", "DELETE", "/accounts"));

        verify(permissionRepository).findByUserIdAndAction("u", "delete");
    }

    // ── Token validation failures ─────────────────────────────────────────────

    @Test
    @DisplayName("Expired/invalid token → AuthenticationException propagated")
    void invalidToken_throwsAuthenticationException() {
        when(jwtAuthenticator.authenticate("bad-token"))
                .thenThrow(new AuthenticationException("Token has expired"));

        assertThatThrownBy(() -> service.authorize(new AuthorizationRequest("bad-token", "GET", "/transactions")))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("expired");
    }

    // ── Path normalization ────────────────────────────────────────────────────

    @Test
    @DisplayName("Leading slash in path is normalized before DB query and matching")
    void leadingSlashNormalized_stillMatches() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("u"));
        when(permissionRepository.findByUserIdAndAction("u", "read"))
                .thenReturn(List.of(allow("u", "read", "transactions"))); // resource has no leading slash

        // path has leading slash — must still match after normalization
        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "GET", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
    }

    // ── Full user scenarios ───────────────────────────────────────────────────

    @Test
    @DisplayName("user456: GET /wallets/wallet-789/transactions → ALLOW (explicit 3-segment rule)")
    void user456_readWalletTransactions_allow() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("user456"));
        when(permissionRepository.findByUserIdAndAction("user456", "read"))
                .thenReturn(List.of(
                        allow("user456", "read", "wallets/*"),
                        allow("user456", "read", "wallets/wallet-789/transactions")
                ));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "GET", "/wallets/wallet-789/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        // More specific rule should win
        assertThat(response.getMatchedPermissions().get(0).getResource())
                .isEqualTo("wallets/wallet-789/transactions");
    }

    @Test
    @DisplayName("user456: POST /wallets/wallet-789/transactions → DENY (no write rule for 3-segment path)")
    void user456_writeWalletTransactions_deny() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("user456"));
        // user456 write permissions: only "wallets/wallet-789" (2 segments)
        when(permissionRepository.findByUserIdAndAction("user456", "write"))
                .thenReturn(List.of(allow("user456", "write", "wallets/wallet-789")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "POST", "/wallets/wallet-789/transactions"));

        // "wallets/wallet-789" (2 segments) must NOT match "wallets/wallet-789/transactions" (3 segments)
        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
    }

    @Test
    @DisplayName("admin789: DELETE /accounts/acc-123/settings → ALLOW (global wildcard)")
    void admin789_deleteDeepPath_allow() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("admin789"));
        when(permissionRepository.findByUserIdAndAction("admin789", "delete"))
                .thenReturn(List.of(allow("admin789", "delete", "*")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "DELETE", "/accounts/acc-123/settings"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    @DisplayName("user789: POST /wallets/wallet-456/transactions/txn-999 → ALLOW (4-segment wildcard)")
    void user789_writeDeepWildcard_allow() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("user789"));
        when(permissionRepository.findByUserIdAndAction("user789", "write"))
                .thenReturn(List.of(allow("user789", "write", "wallets/*/transactions/*")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "POST", "/wallets/wallet-456/transactions/txn-999"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    @DisplayName("[REGRESSION] user with only wallets/* → GET /wallets/wallet-789/transactions → ALLOW (terminal wildcard)")
    void terminalWildcard_grantsAccessToNestedPath() {
        // OLD behaviour: equal-segment check blocked this → DENY
        // NEW behaviour: terminal '*' inherits to all sub-paths → ALLOW
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("user456"));
        when(permissionRepository.findByUserIdAndAction("user456", "read"))
                .thenReturn(List.of(allow("user456", "read", "wallets/*")));  // only wildcard, no explicit 3-seg rule

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "GET", "/wallets/wallet-789/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        assertThat(response.getMatchedPermissions().get(0).getResource()).isEqualTo("wallets/*");
    }

    @Test
    @DisplayName("[REGRESSION] terminal wildcard permission denies sub-path when explicit deny is more specific")
    void terminalWildcardAllow_overriddenByExactDeny_forNestedPath() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("u"));
        when(permissionRepository.findByUserIdAndAction("u", "read"))
                .thenReturn(List.of(
                        allow("u", "read", "wallets/*"),                        // score 3 — broad allow
                        deny("u", "read", "wallets/wallet-789/transactions")    // score 6 — specific deny wins
                ));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "GET", "/wallets/wallet-789/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Unknown HTTP method → IllegalArgumentException → 400 response via handler")
    void unknownMethod_throwsIllegalArgument() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(principal("u"));

        assertThatThrownBy(() -> service.authorize(new AuthorizationRequest("tok", "CONNECT", "/transactions")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("CONNECT");
    }
}