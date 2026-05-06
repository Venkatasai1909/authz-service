package com.venkatasai.auth.authz_service.service;

import com.venkatasai.auth.authz_service.authentication.JwtAuthenticator;
import com.venkatasai.auth.authz_service.authorization.AuthorizationManager;
import com.venkatasai.auth.authz_service.authorization.factory.AuthorizationFactory;
import com.venkatasai.auth.authz_service.authorization.strategy.PolicyEngineStrategy;
import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.dto.response.AuthorizationResponse;
import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.mapper.AuthorizationMapper;
import com.venkatasai.auth.authz_service.model.Decision;
import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.model.User;
import com.venkatasai.auth.authz_service.model.UserPrincipal;
import com.venkatasai.auth.authz_service.policy.engine.PolicyEngine;
import com.venkatasai.auth.authz_service.policy.matcher.DefaultResourceMatcher;
import com.venkatasai.auth.authz_service.policy.resolver.DenyOverridesResolver;
import com.venkatasai.auth.authz_service.policy.scorer.SpecificityScorer;
import com.venkatasai.auth.authz_service.repository.PermissionRepository;
import com.venkatasai.auth.authz_service.repository.UserRepository;
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

    @Mock
    private UserRepository userRepository;

    private AuthorizationServiceImpl service;

    @BeforeEach
    void setUp() {
        // Wire real engine components; only mock JWT, user lookup, and DB
        PolicyEngine policyEngine = new PolicyEngine(
                new DefaultResourceMatcher(),
                new SpecificityScorer(),
                new DenyOverridesResolver()
        );
        PolicyEngineStrategy strategy = new PolicyEngineStrategy(policyEngine);
        AuthorizationFactory factory = new AuthorizationFactory(List.of(strategy));
        AuthorizationManager manager = new AuthorizationManager(factory);

        service = new AuthorizationServiceImpl(
                jwtAuthenticator, permissionRepository, manager, new AuthorizationMapper(), userRepository);
    }

    /**
     * Sets up the two-step identity resolution:
     *  1. JWT "tok" → externalUserId (Clerk sub claim)
     *  2. externalUserId → internal User with internalUserId (DB lookup)
     */
    private void mockIdentity(String token, String externalUserId, String internalUserId) {
        when(jwtAuthenticator.authenticate(token))
                .thenReturn(UserPrincipal.builder().userId(externalUserId).build());
        when(userRepository.findByExternalUserId(externalUserId))
                .thenReturn(java.util.Optional.of(
                        User.builder().id(1).userId(internalUserId).externalUserId(externalUserId).build()));
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
        mockIdentity("tok", "ext-user123", "user123");
        when(permissionRepository.findByUserIdAndAction("user123", "read"))
                .thenReturn(List.of(allow("user123", "read", "transactions")));

        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "GET", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        assertThat(response.getUserId()).isEqualTo("user123");
        assertThat(response.getReason()).isEqualTo("User has read permission for transactions");
        assertThat(response.getMatchedPermissions()).hasSize(1);
    }

    @Test
    @DisplayName("Valid token + explicit deny rule → DENY response")
    void validToken_denyPermission_returnsDeny() {
        mockIdentity("tok", "ext-user123", "user123");
        when(permissionRepository.findByUserIdAndAction("user123", "delete"))
                .thenReturn(List.of(deny("user123", "delete", "transactions")));

        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "DELETE", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        assertThat(response.getUserId()).isEqualTo("user123");
        assertThat(response.getReason()).isEqualTo("Access denied by rule: delete on transactions");
    }

    @Test
    @DisplayName("Valid token + no matching permissions → DENY (default deny)")
    void validToken_noPermissions_returnsDeny() {
        mockIdentity("tok", "ext-user456", "user456");
        when(permissionRepository.findByUserIdAndAction("user456", "write"))
                .thenReturn(List.of());

        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "POST", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        assertThat(response.getReason()).isEqualTo("No matching permission found; default deny applied");
        assertThat(response.getMatchedPermissions()).isEmpty();
    }

    // ── Action mapping ────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST method maps to 'write' action for DB query")
    void postMethod_queriesWithWriteAction() {
        mockIdentity("tok", "ext-u", "u");
        when(permissionRepository.findByUserIdAndAction("u", "write"))
                .thenReturn(List.of());

        service.authorize(new AuthorizationRequest("tok", "POST", "/transactions"));

        verify(permissionRepository).findByUserIdAndAction("u", "write");
        verify(permissionRepository, never()).findByUserIdAndAction(anyString(), eq("POST"));
    }

    @Test
    @DisplayName("DELETE method maps to 'delete' action for DB query")
    void deleteMethod_queriesWithDeleteAction() {
        mockIdentity("tok", "ext-u", "u");
        when(permissionRepository.findByUserIdAndAction("u", "delete"))
                .thenReturn(List.of());

        service.authorize(new AuthorizationRequest("tok", "DELETE", "/accounts"));

        verify(permissionRepository).findByUserIdAndAction("u", "delete");
    }

    // ── Token validation failures ─────────────────────────────────────────────

    @Test
    @DisplayName("Valid token but no Users table entry for externalUserId → AuthenticationException")
    void unknownExternalUser_throwsAuthenticationException() {
        when(jwtAuthenticator.authenticate("tok"))
                .thenReturn(UserPrincipal.builder().userId("ext-unknown").build());
        when(userRepository.findByExternalUserId("ext-unknown"))
                .thenReturn(java.util.Optional.empty());

        assertThatThrownBy(() -> service.authorize(new AuthorizationRequest("tok", "GET", "/transactions")))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("User mapping not found");
    }

    @Test
    @DisplayName("Expired/invalid token → AuthenticationException propagated")
    void invalidToken_throwsAuthenticationException() {
        // authenticate() throws before userRepository is reached
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
        mockIdentity("tok", "ext-u", "u");
        when(permissionRepository.findByUserIdAndAction("u", "read"))
                .thenReturn(List.of(allow("u", "read", "transactions")));

        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "GET", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
    }

    // ── Assignment document sample scenarios ──────────────────────────────────

    @Test
    @DisplayName("user123: GET /transactions → ALLOW")
    void user123_read_transactions_allow() {
        mockIdentity("tok", "ext-user123", "user123");
        when(permissionRepository.findByUserIdAndAction("user123", "read"))
                .thenReturn(List.of(
                        allow("user123", "read", "transactions"),
                        allow("user123", "read", "accounts")));

        AuthorizationResponse response = service.authorize(new AuthorizationRequest("tok", "GET", "/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        assertThat(response.getMatchedPermissions().get(0).getResource()).isEqualTo("transactions");
    }

    @Test
    @DisplayName("user123: DELETE /transactions/txn-456 → DENY (exact rule does not cover child path)")
    void user123_deleteTransactionChild_deny() {
        // Assignment: "Should DENY - user123 explicitly denied delete access"
        // The deny rule "transactions" is exact; it does NOT match child "transactions/txn-456".
        // Result is default DENY (matched_permissions is empty).
        mockIdentity("tok", "ext-user123", "user123");
        when(permissionRepository.findByUserIdAndAction("user123", "delete"))
                .thenReturn(List.of(deny("user123", "delete", "transactions")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "DELETE", "/transactions/txn-456"));

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        assertThat(response.getMatchedPermissions()).isEmpty();
        assertThat(response.getReason()).isEqualTo("No matching permission found; default deny applied");
    }

    @Test
    @DisplayName("user456: GET /wallets/wallet-789/transactions → ALLOW (explicit 3-segment rule wins by specificity)")
    void user456_readWalletTransactions_allow() {
        // Both "wallets/*" (score 5) and "wallets/wallet-789/transactions" (score 12) match.
        // The exact match wins by specificity scoring.
        mockIdentity("tok", "ext-user456", "user456");
        when(permissionRepository.findByUserIdAndAction("user456", "read"))
                .thenReturn(List.of(
                        allow("user456", "read", "wallets/*"),
                        allow("user456", "read", "wallets/wallet-789/transactions")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "GET", "/wallets/wallet-789/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        assertThat(response.getMatchedPermissions().get(0).getResource())
                .isEqualTo("wallets/wallet-789/transactions");
    }

    @Test
    @DisplayName("user789: POST /wallets/wallet-456/transactions/txn-999 → ALLOW (4-segment wildcard)")
    void user789_writeDeepTransaction_allow() {
        mockIdentity("tok", "ext-user789", "user789");
        when(permissionRepository.findByUserIdAndAction("user789", "write"))
                .thenReturn(List.of(allow("user789", "write", "wallets/*/transactions/*")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "POST", "/wallets/wallet-456/transactions/txn-999"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    @DisplayName("user789: POST /wallets/wallet-789/transactions → ALLOW (terminal * absorbs 0 remaining segments)")
    void user789_writeTransactionsCollection_allow() {
        // Assignment: "Should ALLOW - user789 can write to any transaction in any wallet"
        // Pattern "wallets/*/transactions/*" terminal '*' absorbs 0 extra segments here.
        mockIdentity("tok", "ext-user789", "user789");
        when(permissionRepository.findByUserIdAndAction("user789", "write"))
                .thenReturn(List.of(allow("user789", "write", "wallets/*/transactions/*")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "POST", "/wallets/wallet-789/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    @DisplayName("user456: POST /wallets/wallet-789/transactions → DENY (exact rule no child inheritance)")
    void user456_writeWalletTransactions_deny() {
        // Exact rule "wallets/wallet-789" does NOT cover child "wallets/wallet-789/transactions"
        mockIdentity("tok", "ext-user456", "user456");
        when(permissionRepository.findByUserIdAndAction("user456", "write"))
                .thenReturn(List.of(allow("user456", "write", "wallets/wallet-789")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "POST", "/wallets/wallet-789/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        assertThat(response.getMatchedPermissions()).isEmpty();
    }

    @Test
    @DisplayName("admin789: DELETE /accounts/acc-123/settings → ALLOW (global wildcard)")
    void admin789_deleteDeepPath_allow() {
        mockIdentity("tok", "ext-admin789", "admin789");
        when(permissionRepository.findByUserIdAndAction("admin789", "delete"))
                .thenReturn(List.of(allow("admin789", "delete", "*")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "DELETE", "/accounts/acc-123/settings"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        assertThat(response.getMatchedPermissions().get(0).getResource()).isEqualTo("*");
    }

    @Test
    @DisplayName("user456: GET /wallets/wallet-999 → ALLOW (wildcard inheritance)")
    void user456_readUnknownWallet_allow() {
        // Assignment: "Test wildcard inheritance behavior (implementation dependent)"
        mockIdentity("tok", "ext-user456", "user456");
        when(permissionRepository.findByUserIdAndAction("user456", "read"))
                .thenReturn(List.of(
                        allow("user456", "read", "wallets/*"),
                        allow("user456", "read", "wallets/wallet-789/transactions")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "GET", "/wallets/wallet-999"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        assertThat(response.getMatchedPermissions().get(0).getResource()).isEqualTo("wallets/*");
    }

    // ── Regression: terminal wildcard inheritance ─────────────────────────────

    @Test
    @DisplayName("wallets/* alone grants access to nested path via terminal wildcard")
    void terminalWildcard_grantsAccessToNestedPath() {
        mockIdentity("tok", "ext-user456", "user456");
        when(permissionRepository.findByUserIdAndAction("user456", "read"))
                .thenReturn(List.of(allow("user456", "read", "wallets/*")));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "GET", "/wallets/wallet-789/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.ALLOW);
        assertThat(response.getMatchedPermissions().get(0).getResource()).isEqualTo("wallets/*");
    }

    @Test
    @DisplayName("specific deny (score 12) overrides broad wildcard allow (score 5)")
    void terminalWildcardAllow_overriddenByExactDeny_forNestedPath() {
        mockIdentity("tok", "ext-u", "u");
        when(permissionRepository.findByUserIdAndAction("u", "read"))
                .thenReturn(List.of(
                        allow("u", "read", "wallets/*"),                        // score 5  — broad allow
                        deny("u", "read", "wallets/wallet-789/transactions")    // score 12 — specific deny wins
                ));

        AuthorizationResponse response = service.authorize(
                new AuthorizationRequest("tok", "GET", "/wallets/wallet-789/transactions"));

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Unknown HTTP method → IllegalArgumentException → 400 response via handler")
    void unknownMethod_throwsIllegalArgument() {
        // authenticate + user lookup succeed; method mapping throws before DB query
        mockIdentity("tok", "ext-u", "u");

        assertThatThrownBy(() -> service.authorize(new AuthorizationRequest("tok", "CONNECT", "/transactions")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("CONNECT");
    }
}