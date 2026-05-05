package com.venkatasai.auth.authz_service.policy.scorer;

import com.venkatasai.auth.authz_service.util.PathUtils;
import org.springframework.stereotype.Component;

// Specificity scorer using position-weighted scoring.
//
// Let n = total segments in the resource pattern.
// For segment at 0-based index i:
//   weight      = n - i        (left-most = highest weight)
//   exact match : score += weight * 2
//   wildcard *  : score += weight * 1
//
// Global "*" alone: fixed score = 1 (lowest possible).
// Terminal "*": scored once at its position; absorbed extras add nothing.
//
// Example scores for path "wallets/w1/transactions" (n=3, weights 3,2,1):
//   "wallets/w1/transactions"  = 3*2 + 2*2 + 1*2 = 12  (exact)
//   "wallets/w1/[*]"           = 3*2 + 2*2 + 1*1 = 11  (later wildcard)
//   "wallets/[*]/transactions" = 3*2 + 2*1 + 1*2 = 10  (earlier wildcard)
//   "wallets/[*]"              = 2*2 + 1*1        =  5  (shallow terminal)
//   "[*]"                      =                    1  (global)
// (brackets used above to avoid javadoc issues; actual patterns use bare *)
@Component
public class SpecificityScorer implements Scorer {

    @Override
    public int calculateScore(String resource, String path) {
        if (resource == null || path == null) {
            return 0;
        }

        String normResource = PathUtils.normalizePath(resource);
        String normPath     = PathUtils.normalizePath(path);

        // Global wildcard: lowest possible score, loses to every other rule
        if ("*".equals(normResource)) {
            return 1;
        }

        String[] rSegs = normResource.split("/");
        String[] pSegs = normPath.split("/");

        int n     = rSegs.length;  // total pattern segments — defines weights
        int score = 0;
        int r     = 0;
        int p     = 0;
        boolean consumedByTerminalWildcard = false;

        while (r < rSegs.length && p < pSegs.length) {
            String rSeg  = rSegs[r];
            int    weight = n - r;   // position weight: decreases left to right

            if ("*".equals(rSeg)) {
                score += weight;    // wildcard contributes weight * 1

                if (r == rSegs.length - 1) {
                    // Terminal wildcard: absorbs remaining path segments.
                    // Scored once at its position; absorbed extras add nothing.
                    consumedByTerminalWildcard = true;
                    break;
                }

                // Non-terminal wildcard: consumes exactly one path segment
                r++;
                p++;
                continue;
            }

            // Literal segment: must match exactly
            if (rSeg.equals(pSegs[p])) {
                score += weight * 2;    // exact match contributes weight * 2
            } else {
                // Mismatch: scorer should only be called on matched pairs,
                // but be defensive to avoid poisoning the ranking.
                return 0;
            }

            r++;
            p++;
        }

        // ── Special case: path exhausted exactly at terminal wildcard position ────
        // Mirrors the 0-remaining match added in DefaultResourceMatcher.
        // Score the terminal '*' at its position weight so ranking stays consistent.
        if (r == rSegs.length - 1 && "*".equals(rSegs[r]) && p == pSegs.length) {
            score += (n - r); // wildcard contribution at this position
            consumedByTerminalWildcard = true;
        }

        // Terminal wildcard: broke early — valid by definition.
        // Otherwise: both arrays must be fully consumed (exact-depth match).
        if (!consumedByTerminalWildcard && (r != rSegs.length || p != pSegs.length)) {
            return 0;
        }

        return score;
    }

}