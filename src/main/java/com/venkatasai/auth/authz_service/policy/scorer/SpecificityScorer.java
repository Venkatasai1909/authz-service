package com.venkatasai.auth.authz_service.policy.scorer;

import com.venkatasai.auth.authz_service.util.PathUtils;
import org.springframework.stereotype.Component;

// Specificity scorer using position-weighted scoring.
//
// Let totalSegments = total segments in the resource pattern.
// For segment at 0-based resourceIndex:
//   weight      = totalSegments - resourceIndex   (left-most = highest weight)
//   exact match : score += weight * 2
//   wildcard *  : score += weight * 1
//
// Global "*" alone: fixed score = 1 (lowest possible).
// Terminal "*": scored once at its position; absorbed extras add nothing.
//
// Example scores for path "wallets/w1/transactions" (totalSegments=3, weights 3,2,1):
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

        String normalizedResource = PathUtils.normalizePath(resource);
        String normalizedPath     = PathUtils.normalizePath(path);

        // Global wildcard: lowest possible score, loses to every other rule
        if ("*".equals(normalizedResource)) {
            return 1;
        }

        String[] resourceSegments = normalizedResource.split("/");
        String[] pathSegments     = normalizedPath.split("/");

        int totalSegments = resourceSegments.length;  // total pattern segments — defines weights
        int score         = 0;
        int resourceIndex = 0;
        int pathIndex     = 0;
        boolean consumedByTerminalWildcard = false;

        while (resourceIndex < resourceSegments.length && pathIndex < pathSegments.length) {
            String resourceSegment = resourceSegments[resourceIndex];
            int    weight          = totalSegments - resourceIndex;   // position weight: decreases left to right

            if ("*".equals(resourceSegment)) {
                score += weight;    // wildcard contributes weight * 1

                if (resourceIndex == resourceSegments.length - 1) {
                    // Terminal wildcard: absorbs remaining path segments.
                    // Scored once at its position; absorbed extras add nothing.
                    consumedByTerminalWildcard = true;
                    break;
                }

                // Non-terminal wildcard: consumes exactly one path segment
                resourceIndex++;
                pathIndex++;
                continue;
            }

            // Literal segment: must match exactly
            if (resourceSegment.equals(pathSegments[pathIndex])) {
                score += weight * 2;    // exact match contributes weight * 2
            } else {
                // Mismatch: scorer should only be called on matched pairs,
                // but be defensive to avoid poisoning the ranking.
                return 0;
            }

            resourceIndex++;
            pathIndex++;
        }

        // ── Special case: path exhausted exactly at terminal wildcard position ────
        // Mirrors the 0-remaining match added in DefaultResourceMatcher.
        // Score the terminal '*' at its position weight so ranking stays consistent.
        if (resourceIndex == resourceSegments.length - 1 && "*".equals(resourceSegments[resourceIndex]) && pathIndex == pathSegments.length) {
            score += (totalSegments - resourceIndex); // wildcard contribution at this position
            consumedByTerminalWildcard = true;
        }

        // Terminal wildcard: broke early — valid by definition.
        // Otherwise: both arrays must be fully consumed (exact-depth match).
        if (!consumedByTerminalWildcard && (resourceIndex != resourceSegments.length || pathIndex != pathSegments.length)) {
            return 0;
        }

        return score;
    }

}