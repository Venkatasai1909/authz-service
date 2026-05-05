package com.venkatasai.auth.authz_service.policy;

import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.Decision;
import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.policy.engine.PolicyEngine;
import com.venkatasai.auth.authz_service.policy.matcher.DefaultResourceMatcher;
import com.venkatasai.auth.authz_service.policy.model.PolicyEngineResult;
import com.venkatasai.auth.authz_service.policy.resolver.DenyOverridesResolver;
import com.venkatasai.auth.authz_service.policy.scorer.SpecificityScorer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyEngineTest {

    private PolicyEngine engine;

    @BeforeEach
    void setUp() {
        engine = new PolicyEngine(
                new DefaultResourceMatcher(),
                new SpecificityScorer(),
                new DenyOverridesResolver()
        );
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Permission allow(String action, String resource) {
        return Permission.builder().id(1).userId("u").action(action).resource(resource).effect("allow").build();
    }

    private Permission deny(String action, String resource) {
        return Permission.builder().id(2).userId("u").action(action).resource(resource).effect("deny").build();
    }

    private AuthContext ctx(String action, String path) {
        return AuthContext.builder().userId("u").action(action).path(path).build();
    }

    private void assertDecision(PolicyEngineResult result, Decision expected) {
        assertThat(result).isNotNull();
        assertThat(result.getDecision()).isEqualTo(expected);
    }

    private void assertDecisionAndResource(PolicyEngineResult result, Decision expectedDecision, String expectedResource) {
        assertDecision(result, expectedDecision);
        assertThat(result.getPermission()).isNotNull();
        assertThat(result.getPermission().getResource()).isEqualTo(expectedResource);
    }

    // ── Requirement sample scenarios (must all pass) ──────────────────────────

    @Nested
    @DisplayName("Requirement sample scenarios")
    class RequirementScenarios {

        @Test
        void user123_read_transactions_allow() {
            PolicyEngineResult r = engine.evaluate(ctx("read", "transactions"),
                    List.of(allow("read", "transactions")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        void user123_delete_transactions_explicitDeny() {
            PolicyEngineResult r = engine.evaluate(ctx("delete", "transactions"),
                    List.of(deny("delete", "transactions")));
            assertDecision(r, Decision.DENY);
        }

        @Test
        void user456_read_wallet789Transactions_allow() {
            // Has both: broad wildcard and specific permission — specific wins
            List<Permission> perms = List.of(
                    allow("read", "wallets/*"),
                    allow("read", "wallets/wallet-789/transactions")
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions"), perms);
            assertDecisionAndResource(r, Decision.ALLOW, "wallets/wallet-789/transactions");
        }

        @Test
        void user789_write_walletTransactionDeep_allow() {
            PolicyEngineResult r = engine.evaluate(ctx("write", "wallets/wallet-456/transactions/txn-999"),
                    List.of(allow("write", "wallets/*/transactions/*")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        void user456_write_wallet789Transactions_deny() {
            // CRITICAL: "wallets/wallet-789" (exact, no wildcards) must NOT match
            // the sub-path "wallets/wallet-789/transactions" → default DENY
            PolicyEngineResult r = engine.evaluate(ctx("write", "wallets/wallet-789/transactions"),
                    List.of(allow("write", "wallets/wallet-789")));
            assertDecision(r, Decision.DENY);
        }

        @Test
        void admin789_delete_deepPath_allow() {
            PolicyEngineResult r = engine.evaluate(ctx("delete", "accounts/acc-123/settings"),
                    List.of(allow("delete", "*")));
            assertDecision(r, Decision.ALLOW);
        }
    }

    // ── Default deny ──────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Default deny")
    class DefaultDeny {

        @Test
        void emptyPermissions_deny() {
            assertDecision(engine.evaluate(ctx("read", "transactions"), List.of()), Decision.DENY);
        }

        @Test
        void nullPermissions_deny() {
            assertDecision(engine.evaluate(ctx("read", "transactions"), null), Decision.DENY);
        }

        @Test
        void nullAuthContext_deny() {
            assertDecision(engine.evaluate(null, List.of(allow("read", "transactions"))), Decision.DENY);
        }

        @Test
        void noMatchingPermission_deny() {
            assertDecision(engine.evaluate(ctx("read", "transactions"),
                    List.of(allow("read", "accounts"))), Decision.DENY);
        }
    }

    // ── Nested resource inheritance (CRITICAL — old code failed these) ────────

    @Nested
    @DisplayName("Nested resource inheritance via terminal wildcard")
    class NestedInheritance {

        @Test
        @DisplayName("[REGRESSION] wallets/* grants access to wallets/wallet-123/transactions — OLD CODE: DENY")
        void walletStarMatchesTransactionChild() {
            // Old code: resourceSegments.length(2) != pathSegments.length(3) → no match → DENY
            // New code: terminal '*' absorbs remaining → ALLOW
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-123/transactions"),
                    List.of(allow("read", "wallets/*")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        @DisplayName("[REGRESSION] wallets/* grants access to 4-segment nested path — OLD CODE: DENY")
        void walletStarMatchesDeepNestedPath() {
            // Old code: 2 != 4 → no match → DENY
            // New code: terminal '*' → ALLOW
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-123/transactions/txn-456"),
                    List.of(allow("read", "wallets/*")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        void walletStar_grantsAccessToParentCollection() {
            // Terminal '*' absorbs zero remaining segments: "wallets/*" grants access to
            // "wallets" (the collection) as well as any sub-path beneath it.
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets"),
                    List.of(allow("read", "wallets/*")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        void walletTransactionStar_matchesDirectTransaction() {
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions/txn-1"),
                    List.of(allow("read", "wallets/wallet-789/transactions/*")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        void walletTransactionStar_matchesDeeplyNestedTransaction() {
            PolicyEngineResult r = engine.evaluate(ctx("write", "wallets/wallet-456/transactions/txn-999/details"),
                    List.of(allow("write", "wallets/*/transactions/*")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        void fiveLevelDeepNesting_matchedByTerminalWildcard() {
            PolicyEngineResult r = engine.evaluate(ctx("read", "a/b/c/d/e"),
                    List.of(allow("read", "a/*")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        void nonTerminalWildcard_doesNotGrantAccessToChild() {
            // "wallets/*/transactions" ends with a literal — no prefix inheritance
            // "wallets/wallet-789/transactions/txn-123" has 4 segments, pattern has 3 → no match
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions/txn-123"),
                    List.of(allow("read", "wallets/*/transactions")));
            assertDecision(r, Decision.DENY);
        }
    }

    // ── Specificity: more specific beats less specific ─────────────────────────

    @Nested
    @DisplayName("Specificity: more specific rule wins")
    class Specificity {

        @Test
        @DisplayName("Exact path(score 12) beats terminal wildcard(score 5) — returns exact rule")
        void exactBeatsWildcard_allowWins() {
            List<Permission> perms = List.of(
                    allow("read", "wallets/*"),                          // score 5
                    allow("read", "wallets/wallet-789/transactions")     // score 12 — wins
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions"), perms);
            assertDecisionAndResource(r, Decision.ALLOW, "wallets/wallet-789/transactions");
        }

        @Test
        @DisplayName("Exact DENY(score 12) beats wildcard ALLOW(score 5)")
        void exactDenyBeatsWildcardAllow() {
            List<Permission> perms = List.of(
                    allow("read", "wallets/*"),                         // score 5
                    deny("read", "wallets/wallet-789/transactions")     // score 12 — wins
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions"), perms);
            assertDecisionAndResource(r, Decision.DENY, "wallets/wallet-789/transactions");
        }

        @Test
        @DisplayName("Exact ALLOW(score 12) beats wildcard DENY(score 5)")
        void exactAllowBeatsWildcardDeny() {
            List<Permission> perms = List.of(
                    deny("read", "wallets/*"),                          // score 5
                    allow("read", "wallets/wallet-789/transactions")    // score 12 — wins
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions"), perms);
            assertDecisionAndResource(r, Decision.ALLOW, "wallets/wallet-789/transactions");
        }

        @Test
        @DisplayName("wallets/wallet-789/*(score 11) beats wallets/*(score 5) for nested path")
        void deeperWildcardBeatsShallowerWildcard() {
            List<Permission> perms = List.of(
                    deny("read", "wallets/*"),               // score 5
                    allow("read", "wallets/wallet-789/*")    // score 11 — wins
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions"), perms);
            assertDecisionAndResource(r, Decision.ALLOW, "wallets/wallet-789/*");
        }

        @Test
        @DisplayName("Global wildcard(score 1) overridden by specific exact rule(score 6)")
        void globalWildcardOverriddenByExact() {
            List<Permission> perms = List.of(
                    deny("delete", "*"),                     // score 1
                    allow("delete", "wallets/wallet-789")    // score 6 — wins
            );
            PolicyEngineResult r = engine.evaluate(ctx("delete", "wallets/wallet-789"), perms);
            assertDecisionAndResource(r, Decision.ALLOW, "wallets/wallet-789");
        }

        @Test
        @DisplayName("Non-terminal wildcard(score 10) beats terminal wildcard(score 5)")
        void nonTerminalWildcardBeatsTerminalWildcard() {
            List<Permission> perms = List.of(
                    deny("read", "wallets/*"),                       // score 5 (terminal)
                    allow("read", "wallets/*/transactions")          // score 10 (non-terminal + exact) — wins
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions"), perms);
            assertDecisionAndResource(r, Decision.ALLOW, "wallets/*/transactions");
        }

        @Test
        @DisplayName("[REGRESSION] wallets/w1/*(11) beats wallets/*/transactions(10) — literal prefix wins tie")
        void literalPrefixWildcard_beatsWildcardMiddle_tieBreaking() {
            // OLD ALGORITHM BUG: both scored 5 (flat weighting) — tie resolved by deny-override, wrong winner.
            // NEW: position-weighted scoring gives 11 vs 10 — literal prefix always outranks wildcard prefix.
            List<Permission> perms = List.of(
                    deny("read", "wallets/*/transactions"),   // score 10 — wildcard at position 1
                    allow("read", "wallets/w1/*")             // score 11 — wildcard at position 2 — wins
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/w1/transactions"), perms);
            assertDecisionAndResource(r, Decision.ALLOW, "wallets/w1/*");
        }
    }

    // ── Deny overrides Allow at same specificity ──────────────────────────────

    @Nested
    @DisplayName("Deny overrides Allow (same specificity level)")
    class DenyOverrides {

        @Test
        void tiedWildcards_denyWins() {
            List<Permission> perms = List.of(
                    allow("read", "wallets/*"),   // score 3
                    deny("read", "wallets/*")     // score 3 — deny overrides
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-123"), perms);
            assertDecision(r, Decision.DENY);
        }

        @Test
        void tiedExactRules_denyWins() {
            List<Permission> perms = List.of(
                    allow("write", "transactions"),
                    deny("write", "transactions")
            );
            assertDecision(engine.evaluate(ctx("write", "transactions"), perms), Decision.DENY);
        }

        @Test
        void tiedGlobalWildcards_denyWins() {
            List<Permission> perms = List.of(allow("delete", "*"), deny("delete", "*"));
            assertDecision(engine.evaluate(ctx("delete", "anything/anywhere"), perms), Decision.DENY);
        }
    }

    // ── Conflicting wildcard overlaps ─────────────────────────────────────────

    @Nested
    @DisplayName("Conflicting wildcard overlaps")
    class WildcardConflicts {

        @Test
        @DisplayName("Broader deny + narrower allow → narrower wins (specificity)")
        void broadDenyNarrowAllow() {
            // admin has global deny, but specific wallet allowed
            List<Permission> perms = List.of(
                    deny("read", "*"),                   // score 1
                    allow("read", "wallets/wallet-789")  // score 6 — wins
            );
            assertDecisionAndResource(
                    engine.evaluate(ctx("read", "wallets/wallet-789"), perms),
                    Decision.ALLOW, "wallets/wallet-789");
        }

        @Test
        @DisplayName("Overlapping wildcards at different depths — deeper wins")
        void overlappingWildcards_deeperBeatsShallower() {
            List<Permission> perms = List.of(
                    allow("write", "wallets/*"),              // score 5, matches via terminal wildcard
                    deny("write", "wallets/*/transactions/*") // score 16, more specific — wins
            );
            // path: wallets/w-1/transactions/t-1 (4 segments)
            PolicyEngineResult r = engine.evaluate(ctx("write", "wallets/w-1/transactions/t-1"), perms);
            assertDecisionAndResource(r, Decision.DENY, "wallets/*/transactions/*");
        }

        @Test
        @DisplayName("Three overlapping rules — most specific one wins")
        void threeOverlappingRules_mostSpecificWins() {
            List<Permission> perms = List.of(
                    deny("read", "*"),                                    // score 1
                    deny("read", "wallets/*"),                            // score 5
                    allow("read", "wallets/wallet-789/transactions")      // score 12 — wins
            );
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789/transactions"), perms);
            assertDecisionAndResource(r, Decision.ALLOW, "wallets/wallet-789/transactions");
        }
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {

        @Test
        void leadingSlashNormalized() {
            // AuthContext already normalizes, but engine should handle raw slashes too
            AuthContext context = AuthContext.builder().userId("u").action("read").path("/transactions").build();
            PolicyEngineResult r = engine.evaluate(context, List.of(allow("read", "transactions")));
            assertDecision(r, Decision.ALLOW);
        }

        @Test
        void singleWildcard_matchesSiblings() {
            // "wallets/*" should match different wallets
            assertDecision(engine.evaluate(ctx("read", "wallets/wallet-1"), List.of(allow("read", "wallets/*"))), Decision.ALLOW);
            assertDecision(engine.evaluate(ctx("read", "wallets/wallet-2"), List.of(allow("read", "wallets/*"))), Decision.ALLOW);
            assertDecision(engine.evaluate(ctx("read", "wallets/wallet-999"), List.of(allow("read", "wallets/*"))), Decision.ALLOW);
        }

        @Test
        void engineIsActionAgnostic_pathMatchDeterminesDecision() {
            // The PolicyEngine evaluates path matching only; action filtering is applied
            // upstream at the repository layer before permissions reach the engine.
            // A permission with a different stored action still produces ALLOW if the path matches,
            // because the engine does not re-validate the action field.
            PolicyEngineResult r = engine.evaluate(ctx("read", "wallets/wallet-789"),
                    List.of(allow("write", "wallets/wallet-789")));
            assertDecision(r, Decision.ALLOW);
        }
    }
}