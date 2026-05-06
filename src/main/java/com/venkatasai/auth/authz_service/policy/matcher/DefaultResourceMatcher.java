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

        String normalizedResource = PathUtils.normalizePath(resource);
        String normalizedPath     = PathUtils.normalizePath(path);

        // Global wildcard matches any path at any depth
        if ("*".equals(normalizedResource)) {
            return true;
        }

        String[] resourceSegments = normalizedResource.split("/");
        String[] pathSegments     = normalizedPath.split("/");

        int resourceIndex = 0;
        int pathIndex     = 0;

        while (resourceIndex < resourceSegments.length && pathIndex < pathSegments.length) {
            String resourceSegment = resourceSegments[resourceIndex];

            if ("*".equals(resourceSegment)) {
                boolean isTerminal = (resourceIndex == resourceSegments.length - 1);

                if (isTerminal) {
                    // Terminal wildcard: absorbs this segment plus all remaining path segments.
                    // The while-loop guarantees pathIndex < pathSegments.length here, so at least one segment
                    // is consumed by this branch. The 0-remaining case (path already exhausted
                    // when the loop exits) is handled by the check after the loop.
                    log.trace("Terminal wildcard at resourceIndex={} matched remaining path from pathIndex={}", resourceIndex, pathIndex);
                    return true;
                }

                // Non-terminal wildcard: consume exactly one path segment
                resourceIndex++;
                pathIndex++;
                continue;
            }

            // Literal segment: must match exactly
            if (!resourceSegment.equals(pathSegments[pathIndex])) {
                log.trace("Segment mismatch at resourceIndex={}: expected='{}' got='{}'", resourceIndex, resourceSegment, pathSegments[pathIndex]);
                return false;
            }

            resourceIndex++;
            pathIndex++;
        }

        // ── Special case: path exhausted exactly at terminal wildcard position ────
        // Handles patterns like "wallets/*/transactions/*" matching "wallets/wallet-789/transactions"
        // where the terminal '*' absorbs zero remaining path segments.
        // Note: "wallets/*" also matches "wallets" (the collection itself) under this rule.
        if (resourceIndex == resourceSegments.length - 1 && "*".equals(resourceSegments[resourceIndex]) && pathIndex == pathSegments.length) {
            log.trace("Terminal wildcard at resourceIndex={} matched empty remainder (0-remaining)", resourceIndex);
            return true;
        }

        // Both arrays must be fully consumed for an exact match.
        // If one is exhausted before the other it is either:
        //   - pattern shorter than path (literal overshoot) → false
        //   - pattern longer than path (path too short)     → false
        boolean matched = (resourceIndex == resourceSegments.length && pathIndex == pathSegments.length);
        log.trace("Exact-length check: resourceExhausted={} pathExhausted={} matched={}", resourceIndex == resourceSegments.length, pathIndex == pathSegments.length, matched);
        return matched;
    }

}