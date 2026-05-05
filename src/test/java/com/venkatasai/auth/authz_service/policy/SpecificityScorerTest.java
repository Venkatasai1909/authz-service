package com.venkatasai.auth.authz_service.policy;

import com.venkatasai.auth.authz_service.policy.scorer.SpecificityScorer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

// Position-weighted specificity scoring rules (weight = n - i):
//
//   n = total pattern segments
//   i = 0-based segment index (left = higher weight)
//
//   Exact literal segment   : score += (n-i) * 2
//   Wildcard segment        : score += (n-i) * 1
//   Terminal wildcard       : scored once at its position; absorbed extras add nothing
//   Global "*" alone        : fixed score = 1 (lowest possible)
//
// Example (n=3, path "wallets/w1/transactions", weights 3,2,1):
//   "wallets/w1/transactions"  = 3*2 + 2*2 + 1*2 = 12  (exact)
//   "wallets/w1/*"             = 3*2 + 2*2 + 1*1 = 11  (later wildcard)
//   "wallets/*/transactions"   = 3*2 + 2*1 + 1*2 = 10  (earlier wildcard)
//   "wallets/*"                = 2*2 + 1*1        =  5  (shallow terminal)
//   "*"                        =                    1  (global)
class SpecificityScorerTest {

    private SpecificityScorer scorer;

    @BeforeEach
    void setUp() {
        scorer = new SpecificityScorer();
    }

    // ── Global wildcard ───────────────────────────────────────────────────────

    @Nested
    @DisplayName("Global wildcard")
    class GlobalWildcard {

        @Test
        @DisplayName("'*' alone → score 1 regardless of path depth")
        void globalWildcard_alwaysScore1() {
            assertThat(scorer.calculateScore("*", "transactions")).isEqualTo(1);
            assertThat(scorer.calculateScore("*", "wallets/wallet-789")).isEqualTo(1);
            assertThat(scorer.calculateScore("*", "wallets/wallet-789/transactions/txn-123")).isEqualTo(1);
        }
    }

    // ── Exact matches ─────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Exact matches")
    class ExactMatches {

        @Test
        @DisplayName("Single exact segment: n=1, weight=1 → 1*2 = 2")
        void singleExactSegment() {
            assertThat(scorer.calculateScore("transactions", "transactions")).isEqualTo(2);
        }

        @Test
        @DisplayName("Two exact segments: n=2, weights 2,1 → 2*2 + 1*2 = 6")
        void twoExactSegments() {
            assertThat(scorer.calculateScore("wallets/wallet-789", "wallets/wallet-789")).isEqualTo(6);
        }

        @Test
        @DisplayName("Three exact segments: n=3, weights 3,2,1 → 3*2 + 2*2 + 1*2 = 12")
        void threeExactSegments() {
            assertThat(scorer.calculateScore("wallets/wallet-789/transactions",
                    "wallets/wallet-789/transactions")).isEqualTo(12);
        }
    }

    // ── Wildcard scoring ──────────────────────────────────────────────────────

    @Nested
    @DisplayName("Wildcard scoring")
    class WildcardScoring {

        @Test
        @DisplayName("wallets/* vs direct child: n=2, weights 2,1 → 2*2 + 1*1 = 5")
        void singleTerminalWildcard_directChild() {
            assertThat(scorer.calculateScore("wallets/*", "wallets/wallet-789")).isEqualTo(5);
        }

        @Test
        @DisplayName("[CRITICAL] wallets/* vs nested path → still 5 (terminal wildcard scored once, absorbed extras add nothing)")
        void terminalWildcard_nestedPath_sameScore() {
            // Terminal '*' absorbs all remaining segments but scores only at its position.
            // wallets/* (n=2): 2*2 + 1*1 = 5, regardless of how deep the path goes.
            // This ensures 'wallets/wallet-789/transactions' (score 12) always beats
            // 'wallets/*' (score 5) for the same nested path.
            assertThat(scorer.calculateScore("wallets/*", "wallets/wallet-789/transactions")).isEqualTo(5);
            assertThat(scorer.calculateScore("wallets/*", "wallets/wallet-789/transactions/txn-123")).isEqualTo(5);
        }

        @Test
        @DisplayName("wallets/wallet-789/* vs 3-seg path: n=3, weights 3,2,1 → 3*2 + 2*2 + 1*1 = 11")
        void terminalWildcard_moreSpecificPrefix_higherScore() {
            // More literal segments before terminal '*' = higher score (due to higher weights)
            assertThat(scorer.calculateScore("wallets/wallet-789/*",
                    "wallets/wallet-789/transactions")).isEqualTo(11);
        }

        @Test
        @DisplayName("Non-terminal wildcard: wallets/*/transactions: n=3, weights 3,2,1 → 3*2 + 2*1 + 1*2 = 10")
        void nonTerminalWildcard_threeSegments() {
            assertThat(scorer.calculateScore("wallets/*/transactions",
                    "wallets/wallet-789/transactions")).isEqualTo(10);
        }

        @Test
        @DisplayName("Mixed wildcards: wallets/*/transactions/*: n=4, weights 4,3,2,1 → 4*2 + 3*1 + 2*2 + 1*1 = 16")
        void mixedWildcards_fourSegPattern() {
            assertThat(scorer.calculateScore("wallets/*/transactions/*",
                    "wallets/wallet-456/transactions/txn-999")).isEqualTo(16);
        }
    }

    // ── Tie-breaking: wildcard position matters ───────────────────────────────

    @Nested
    @DisplayName("Tie-breaking: wildcard position determines rank")
    class TieBreaking {

        // OLD ALGORITHM BUG: wallets/w1/* and wallets/*/transactions BOTH scored 5.
        // NEW algorithm fixes this via position-weighted scoring.

        @Test
        @DisplayName("[REGRESSION] wallets/w1/*(11) beats wallets/*/transactions(10) — literal prefix wins over literal suffix")
        void literalPrefixWildcard_beatsWildcardPrefix_forSamePath() {
            // path: wallets/w1/transactions (n=3 for both patterns)
            // wallets/w1/*:           3*2(wallets) + 2*2(w1) + 1*1(*) = 11  — wildcards late
            // wallets/*/transactions: 3*2(wallets) + 2*1(*) + 1*2(transactions) = 10 — wildcard early
            String path = "wallets/w1/transactions";

            int literalPrefix  = scorer.calculateScore("wallets/w1/*", path);           // 11
            int wildcardMiddle = scorer.calculateScore("wallets/*/transactions", path);  // 10

            assertThat(literalPrefix).isEqualTo(11);
            assertThat(wildcardMiddle).isEqualTo(10);
            assertThat(literalPrefix).isGreaterThan(wildcardMiddle);
        }

        @Test
        @DisplayName("Later wildcard position always ranks higher than earlier wildcard position")
        void laterWildcard_beatsEarlierWildcard_sameDepth() {
            // Three-segment patterns, one wildcard each, path wallets/w1/transactions
            // wallets/w1/*           = 3*2 + 2*2 + 1*1 = 11  (wildcard at index 2)
            // wallets/*/transactions = 3*2 + 2*1 + 1*2 = 10  (wildcard at index 1)
            String path = "wallets/w1/transactions";

            assertThat(scorer.calculateScore("wallets/w1/*", path))
                    .isGreaterThan(scorer.calculateScore("wallets/*/transactions", path));
        }

        @Test
        @DisplayName("Deeper terminal wildcard(11) beats shallower terminal wildcard(5) for same path")
        void deeperTerminalWildcard_beatsShallowerTerminalWildcard() {
            // wallets/wallet-789/* (n=3): 3*2 + 2*2 + 1*1 = 11
            // wallets/*            (n=2): 2*2 + 1*1       =  5
            String path = "wallets/wallet-789/transactions";

            int deeper   = scorer.calculateScore("wallets/wallet-789/*", path); // 11
            int shallower = scorer.calculateScore("wallets/*", path);           //  5

            assertThat(deeper).isEqualTo(11);
            assertThat(shallower).isEqualTo(5);
            assertThat(deeper).isGreaterThan(shallower);
        }
    }

    // ── Correct ordering (key invariant) ─────────────────────────────────────

    @Nested
    @DisplayName("Ordering invariants")
    class Ordering {

        @Test
        @DisplayName("exact(12) > non-terminal-wildcard(10) > terminal-wildcard(5) > global(1)")
        void correctOrdering_forNestedPath() {
            String path = "wallets/wallet-789/transactions";

            int exact    = scorer.calculateScore("wallets/wallet-789/transactions", path); // 12
            int specific = scorer.calculateScore("wallets/*/transactions", path);          // 10
            int broad    = scorer.calculateScore("wallets/*", path);                       //  5
            int global   = scorer.calculateScore("*", path);                               //  1

            assertThat(exact).isEqualTo(12);
            assertThat(specific).isEqualTo(10);
            assertThat(broad).isEqualTo(5);
            assertThat(global).isEqualTo(1);

            assertThat(exact).isGreaterThan(specific);
            assertThat(specific).isGreaterThan(broad);
            assertThat(broad).isGreaterThan(global);
        }

        @Test
        @DisplayName("Exact path(6) beats terminal wildcard(5) with same prefix")
        void exactBeatsTerminalWildcard() {
            String path = "wallets/wallet-789";

            int exact    = scorer.calculateScore("wallets/wallet-789", path); // 6
            int wildcard = scorer.calculateScore("wallets/*", path);          // 5

            assertThat(exact).isEqualTo(6);
            assertThat(wildcard).isEqualTo(5);
            assertThat(exact).isGreaterThan(wildcard);
        }
    }

    // ── Defensive / edge cases ────────────────────────────────────────────────

    @Nested
    @DisplayName("Defensive and edge cases")
    class EdgeCases {

        @Test
        @DisplayName("Exact pattern vs deeper path → 0 (depth mismatch, matcher would not call scorer)")
        void exactPatternVsLongerPath_zeroScore() {
            assertThat(scorer.calculateScore("wallets/wallet-789",
                    "wallets/wallet-789/transactions")).isEqualTo(0);
        }

        @Test
        @DisplayName("Segment mismatch → 0")
        void segmentMismatch_zeroScore() {
            assertThat(scorer.calculateScore("accounts/acc-1", "wallets/wallet-1")).isEqualTo(0);
        }

        @Test
        @DisplayName("Null inputs → 0")
        void nullInputs() {
            assertThat(scorer.calculateScore(null, "transactions")).isEqualTo(0);
            assertThat(scorer.calculateScore("transactions", null)).isEqualTo(0);
        }

        @Test
        @DisplayName("Leading slash normalized before scoring")
        void leadingSlash_normalized() {
            assertThat(scorer.calculateScore("/transactions", "/transactions"))
                    .isEqualTo(scorer.calculateScore("transactions", "transactions"));
        }
    }
}