package com.venkatasai.auth.authz_service.policy.engine;

import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.Decision;
import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.policy.matcher.ResourceMatcher;
import com.venkatasai.auth.authz_service.policy.model.PolicyEngineResult;
import com.venkatasai.auth.authz_service.policy.model.ScoredPermission;
import com.venkatasai.auth.authz_service.policy.resolver.ConflictResolver;
import com.venkatasai.auth.authz_service.policy.scorer.Scorer;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Slf4j
@Component
@AllArgsConstructor
public class PolicyEngine {

    private final ResourceMatcher matcher;
    private final Scorer scorer;
    private final ConflictResolver resolver;

    public PolicyEngineResult evaluate(AuthContext authContext, List<Permission> permissions) {

        // ── Guard: no context or no permissions to evaluate ─────────────────
        if (authContext == null || permissions == null || permissions.isEmpty()) {
            log.debug("[POLICY] No input to evaluate (authContext={}, permCount={}) → default DENY",
                    authContext != null ? authContext.getUserId() : "null",
                    permissions == null ? "null" : 0);
            return PolicyEngineResult.buildDefaultOutput();
        }

        log.debug("[POLICY] START  userId={} action={} path={} candidatePermissions={}",
                authContext.getUserId(), authContext.getAction(),
                authContext.getPath(), permissions.size());

        // ── Phase 1: Resource matching ───────────────────────────────────────
        List<Permission> matched = permissions.stream()
                .filter(p -> {
                    boolean m = matcher.matches(p.getResource(), authContext.getPath());
                    log.debug("[MATCH]   resource='{}' effect='{}' → {}",
                            p.getResource(), p.getEffect(), m ? "MATCH" : "no match");
                    return m;
                })
                .toList();

        log.debug("[POLICY] MATCH  {}/{} permission(s) matched path='{}'",
                matched.size(), permissions.size(), authContext.getPath());

        if (matched.isEmpty()) {
            log.debug("[POLICY] DECISION  no match → default DENY (userId={} action={} path={})",
                    authContext.getUserId(), authContext.getAction(), authContext.getPath());
            return PolicyEngineResult.buildDefaultOutput();
        }

        // ── Phase 2: Specificity scoring ─────────────────────────────────────
        List<ScoredPermission> scored = matched.stream()
                .map(p -> {
                    int s = scorer.calculateScore(p.getResource(), authContext.getPath());
                    log.debug("[SCORE]   resource='{}' effect='{}' score={}",
                            p.getResource(), p.getEffect(), s);
                    return new ScoredPermission(p, s);
                })
                .toList();

        // ── Phase 3: Select the most specific candidates ─────────────────────
        int topScore = topScore(scored);
        List<ScoredPermission> topScored = scored.stream()
                .filter(sp -> sp.score() == topScore)
                .toList();

        log.debug("[POLICY] TOP    topScore={} candidates={}",
                topScore, topScored.stream()
                        .map(sp -> "'" + sp.permission().getResource() + "'[" + sp.permission().getEffect() + "]")
                        .toList());

        // ── Phase 4a: Single winner ───────────────────────────────────────────
        if (topScored.size() == 1) {
            ScoredPermission winner = topScored.getFirst();
            log.debug("[POLICY] DECISION  single winner resource='{}' effect='{}' → {}",
                    winner.permission().getResource(),
                    winner.permission().getEffect(),
                    winner.permission().getDecision());
            return new PolicyEngineResult(winner.permission(), winner.permission().getDecision());
        }

        // ── Phase 4b: Tie → conflict resolver (deny overrides allow) ─────────
        Decision decision = resolver.resolve(topScored);
        Optional<ScoredPermission> resolved = topScored.stream()
                .filter(sp -> sp.permission().getDecision() == decision)
                .findFirst();

        log.debug("[POLICY] CONFLICT  {} candidates tied at score={} → resolver decision={}",
                topScored.size(), topScore, decision);

        log.debug("[POLICY] DECISION  userId={} action={} path='{}' → {}",
                authContext.getUserId(), authContext.getAction(),
                authContext.getPath(), decision);

        return resolved
                .map(sp -> new PolicyEngineResult(sp.permission(), decision))
                .orElseGet(PolicyEngineResult::buildDefaultOutput);
    }

    private int topScore(List<ScoredPermission> scored) {
        return scored.stream()
                .mapToInt(ScoredPermission::score)
                .max()
                .orElse(0);
    }
}