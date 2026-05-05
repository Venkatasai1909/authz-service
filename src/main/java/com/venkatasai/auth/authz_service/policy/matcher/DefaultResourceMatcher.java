package com.venkatasai.auth.authz_service.policy.matcher;

import com.venkatasai.auth.authz_service.util.PathUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class DefaultResourceMatcher implements ResourceMatcher {

    @Override
    public boolean matches(String resource, String path) {
        if (resource == null || path == null) {
            return false;
        }

        String normResource = PathUtils.normalizePath(resource);
        String normPath     = PathUtils.normalizePath(path);

        // Empty path after normalization: only the global wildcard matches
        if (normPath.isEmpty()) {
            return "*".equals(normResource);
        }

        // Global wildcard matches any path at any depth
        if ("*".equals(normResource)) {
            return true;
        }

        String[] rSegs = normResource.split("/");
        String[] pSegs = normPath.split("/");

        int r = 0;
        int p = 0;

        while (r < rSegs.length && p < pSegs.length) {
            String rSeg = rSegs[r];

            if ("*".equals(rSeg)) {
                boolean isTerminal = (r == rSegs.length - 1);

                if (isTerminal) {
                    // Terminal wildcard: absorbs this segment plus all remaining path segments.
                    // The while-loop guarantees p < pSegs.length here, so at least one segment
                    // is consumed by this branch. The 0-remaining case (path already exhausted
                    // when the loop exits) is handled by the check after the loop.
                    log.trace("Terminal wildcard at r={} matched remaining path from p={}", r, p);
                    return true;
                }

                // Non-terminal wildcard: consume exactly one path segment
                r++;
                p++;
                continue;
            }

            // Literal segment: must match exactly
            if (!rSeg.equals(pSegs[p])) {
                log.trace("Segment mismatch at r={}: expected='{}' got='{}'", r, rSeg, pSegs[p]);
                return false;
            }

            r++;
            p++;
        }

        // ── Special case: path exhausted exactly at terminal wildcard position ────
        // Handles patterns like "wallets/*/transactions/*" matching "wallets/wallet-789/transactions"
        // where the terminal '*' absorbs zero remaining path segments.
        // Note: "wallets/*" also matches "wallets" (the collection itself) under this rule.
        if (r == rSegs.length - 1 && "*".equals(rSegs[r]) && p == pSegs.length) {
            log.trace("Terminal wildcard at r={} matched empty remainder (0-remaining)", r);
            return true;
        }

        // Both arrays must be fully consumed for an exact match.
        // If one is exhausted before the other it is either:
        //   - pattern shorter than path (literal overshoot) → false
        //   - pattern longer than path (path too short)     → false
        boolean matched = (r == rSegs.length && p == pSegs.length);
        log.trace("Exact-length check: rExhausted={} pExhausted={} matched={}", r == rSegs.length, p == pSegs.length, matched);
        return matched;
    }

}