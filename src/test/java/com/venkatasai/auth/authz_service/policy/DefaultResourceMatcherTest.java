package com.venkatasai.auth.authz_service.policy;

import com.venkatasai.auth.authz_service.policy.matcher.DefaultResourceMatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for DefaultResourceMatcher.
 *
 * Key semantic rules under test:
 *  - "*" alone            = global wildcard (any path, any depth)
 *  - Non-terminal "*"     = one path segment exactly
 *  - Terminal "*"         = one OR MORE remaining path segments (hierarchical inheritance)
 *  - No wildcards         = strict exact match
 */
class DefaultResourceMatcherTest {

    private DefaultResourceMatcher matcher;

    @BeforeEach
    void setUp() {
        matcher = new DefaultResourceMatcher();
    }

    // ── Exact matches ─────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Exact (no-wildcard) matches — strict equality only")
    class ExactMatches {

        @Test
        void singleSegment_exactMatch() {
            assertThat(matcher.matches("transactions", "transactions")).isTrue();
        }

        @Test
        void twoSegments_exactMatch() {
            assertThat(matcher.matches("wallets/wallet-789", "wallets/wallet-789")).isTrue();
        }

        @Test
        void threeSegments_exactMatch() {
            assertThat(matcher.matches("wallets/wallet-789/transactions", "wallets/wallet-789/transactions")).isTrue();
        }

        @Test
        void differentValue_noMatch() {
            assertThat(matcher.matches("transactions", "accounts")).isFalse();
        }

        @Test
        void exactPatternMustNotMatchChild() {
            // CRITICAL: "wallets/wallet-789" is an exact rule.
            // It must NOT grant access to "wallets/wallet-789/transactions".
            // This preserves the DENY scenario for user456 → POST /wallets/wallet-789/transactions.
            assertThat(matcher.matches("wallets/wallet-789", "wallets/wallet-789/transactions")).isFalse();
        }

        @Test
        void exactPatternMustNotMatchDeepChild() {
            assertThat(matcher.matches("wallets/wallet-789", "wallets/wallet-789/transactions/txn-123")).isFalse();
        }

        @Test
        void longerPatternMustNotMatchShorterPath() {
            assertThat(matcher.matches("wallets/wallet-789/transactions", "wallets/wallet-789")).isFalse();
        }
    }

    // ── Global wildcard ───────────────────────────────────────────────────────

    @Nested
    @DisplayName("Global wildcard '*'")
    class GlobalWildcard {

        @Test
        void matchesSingleSegment() {
            assertThat(matcher.matches("*", "transactions")).isTrue();
        }

        @Test
        void matchesTwoSegments() {
            assertThat(matcher.matches("*", "wallets/wallet-789")).isTrue();
        }

        @Test
        void matchesDeepPath() {
            assertThat(matcher.matches("*", "accounts/acc-123/settings")).isTrue();
        }

        @Test
        void matchesFourLevels() {
            assertThat(matcher.matches("*", "wallets/wallet-789/transactions/txn-123")).isTrue();
        }
    }

    // ── Terminal wildcard: hierarchical / prefix matching ─────────────────────

    @Nested
    @DisplayName("Terminal '*': hierarchical inheritance (CRITICAL)")
    class TerminalWildcard {

        // ── These two tests FAILED in the old equal-segment implementation ──

        @Test
        @DisplayName("[REGRESSION] wallets/* matches wallets/wallet-123/transactions — OLD CODE RETURNED FALSE")
        void terminalWildcard_matchesDirectChild_andNestedChild() {
            // Old code: resourceSegments.length(2) != pathSegments.length(3) → false
            // New code: terminal '*' absorbs all remaining segments → true
            assertThat(matcher.matches("wallets/*", "wallets/wallet-123/transactions")).isTrue();
        }

        @Test
        @DisplayName("[REGRESSION] wallets/* matches deeply nested path — OLD CODE RETURNED FALSE")
        void terminalWildcard_matchesDeepNesting() {
            // Old code: 2 != 4 → false
            // New code: terminal '*' absorbs remaining → true
            assertThat(matcher.matches("wallets/*", "wallets/wallet-123/transactions/txn-456")).isTrue();
        }

        @Test
        void terminalWildcard_matchesDirectChild() {
            assertThat(matcher.matches("wallets/*", "wallets/wallet-789")).isTrue();
        }

        @Test
        void terminalWildcard_matchesParentCollection() {
            // Terminal '*' absorbs zero remaining segments: "wallets/*" also matches "wallets"
            // (the collection itself). This is consistent with "wallets/*/transactions/*"
            // matching "wallets/wallet-789/transactions" (terminal '*' absorbs 0 segments).
            assertThat(matcher.matches("wallets/*", "wallets")).isTrue();
        }

        @Test
        void terminalWildcard_doesNotMatchSiblingPrefix() {
            assertThat(matcher.matches("wallets/*", "accounts/acc-123")).isFalse();
        }

        @Test
        void terminalWildcard_fiveLevelsDeep() {
            assertThat(matcher.matches("wallets/*", "wallets/w/a/b/c/d")).isTrue();
        }
    }

    // ── Non-terminal wildcard: single-segment matching ────────────────────────

    @Nested
    @DisplayName("Non-terminal '*': matches exactly one segment, then continues")
    class NonTerminalWildcard {

        @Test
        void nonTerminalWildcard_matchesExactDepth() {
            assertThat(matcher.matches("wallets/*/transactions", "wallets/wallet-789/transactions")).isTrue();
        }

        @Test
        void nonTerminalWildcard_doesNotMatchDeeper() {
            // "wallets/*/transactions" ends in a literal; no terminal wildcard to absorb the extra segment
            assertThat(matcher.matches("wallets/*/transactions", "wallets/wallet-789/transactions/txn-123")).isFalse();
        }

        @Test
        void nonTerminalWildcard_doesNotMatchShallower() {
            assertThat(matcher.matches("wallets/*/transactions", "wallets/wallet-789")).isFalse();
        }

        @Test
        void nonTerminalWildcard_matchesDifferentWalletId() {
            assertThat(matcher.matches("wallets/*/transactions", "wallets/wallet-999/transactions")).isTrue();
        }
    }

    // ── Mixed (non-terminal + terminal) wildcard ──────────────────────────────

    @Nested
    @DisplayName("Mixed wildcards: 'wallets/*/transactions/*'")
    class MixedWildcards {

        @Test
        void matchesExactDepthFourSegments() {
            assertThat(matcher.matches("wallets/*/transactions/*", "wallets/wallet-456/transactions/txn-999")).isTrue();
        }

        @Test
        @DisplayName("[REGRESSION] Terminal '*' in 4-seg pattern absorbs 5th segment — OLD CODE RETURNED FALSE")
        void terminalWildcardInFourSegPattern_matchesFiveSegPath() {
            // Old code: 4 != 5 → false
            // New code: terminal '*' absorbs 5th segment → true
            assertThat(matcher.matches("wallets/*/transactions/*", "wallets/wallet-456/transactions/txn-999/details")).isTrue();
        }

        @Test
        void matchesThreeSegmentPath_terminalWildcardAbsorbsZero() {
            // Terminal '*' absorbs zero remaining segments: "wallets/*/transactions/*" matches
            // "wallets/wallet-456/transactions" (the collection endpoint, 3 segments).
            assertThat(matcher.matches("wallets/*/transactions/*", "wallets/wallet-456/transactions")).isTrue();
        }

        @Test
        void doesNotMatchWrongLiteralSegment() {
            assertThat(matcher.matches("wallets/*/transactions/*", "wallets/wallet-456/accounts/acc-1")).isFalse();
        }
    }

    // ── Path normalization ────────────────────────────────────────────────────

    @Nested
    @DisplayName("Path normalization (leading/trailing slashes)")
    class Normalization {

        @Test
        void leadingSlashInPath() {
            assertThat(matcher.matches("transactions", "/transactions")).isTrue();
        }

        @Test
        void leadingSlashInResource() {
            assertThat(matcher.matches("/transactions", "transactions")).isTrue();
        }

        @Test
        void trailingSlash() {
            assertThat(matcher.matches("wallets/wallet-789/", "/wallets/wallet-789")).isTrue();
        }

        @Test
        void leadingSlashWithTerminalWildcard() {
            assertThat(matcher.matches("/wallets/*", "/wallets/wallet-789/transactions")).isTrue();
        }
    }

    // ── Null / edge cases ─────────────────────────────────────────────────────

    @Nested
    @DisplayName("Null and edge cases")
    class NullEdgeCases {

        @Test
        void nullResource_returnsFalse() {
            assertThat(matcher.matches(null, "transactions")).isFalse();
        }

        @Test
        void nullPath_returnsFalse() {
            assertThat(matcher.matches("transactions", null)).isFalse();
        }

        @Test
        void bothNull_returnsFalse() {
            assertThat(matcher.matches(null, null)).isFalse();
        }

        @Test
        void globalWildcard_doesNotMatchEmptyPath() {
            // Empty path after normalization — only global '*' matches
            // (empty path "/" normalizes to "" which is treated as empty)
            assertThat(matcher.matches("wallets/*", "")).isFalse();
        }
    }
}
