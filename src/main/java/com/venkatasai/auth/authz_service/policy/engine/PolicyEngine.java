package com.venkatasai.auth.authz_service.policy.engine;

import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.Decision;
import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.model.PolicyEngineResult;
import com.venkatasai.auth.authz_service.policy.matcher.ResourceMatcher;
import com.venkatasai.auth.authz_service.policy.model.ScoredPermission;
import com.venkatasai.auth.authz_service.policy.resolver.ConflictResolver;
import com.venkatasai.auth.authz_service.policy.scorer.Scorer;

import java.util.List;
import java.util.Optional;

public class PolicyEngine {
    private final ResourceMatcher matcher;
    private final ConflictResolver resolver;
    private final Scorer scorer;

    public PolicyEngine(ResourceMatcher matcher,
                        Scorer scorer,
                        ConflictResolver resolver) {
        this.matcher = matcher;
        this.scorer = scorer;
        this.resolver = resolver;
    }

    public PolicyEngineResult evaluate(AuthContext authContext, List<Permission> permissions){
        if(authContext == null || permissions == null || permissions.isEmpty()){
            return PolicyEngineResult.buildDefaultOutput();
        }

        // 1. ResourceMatching
        List<Permission> resourceMatchingPermissions = permissions.stream()
                .filter(permission -> matcher.matches(permission.getResource(), authContext.getPath()))
                .toList();

        // 2. Score for each Permission
        List<ScoredPermission> scoredPermissions = resourceMatchingPermissions.stream()
                .map(permission -> new ScoredPermission(permission,
                        scorer.calculateScore(permission.getResource(), authContext.getPath())))
                .toList();

        int topScorer = getTopScoreOfPermissions(scoredPermissions);
        List<ScoredPermission> topScoredPermissions = scoredPermissions.stream()
                .filter(scoredPermission -> scoredPermission.score() == topScorer)
                .toList();

        // 3. Only Single top Scored Permission exists, then just return it
        if(topScoredPermissions.size() == 1){
            ScoredPermission topScoredPermission = topScoredPermissions.getFirst();
            return new PolicyEngineResult(topScoredPermission.permission(), topScoredPermission.permission().getDecision());
        }

        // 4. There is a conflict between multiple top Scored Permissions
        Decision decision = resolver.resolve(topScoredPermissions);
        Optional<ScoredPermission> finalScoredPermission = topScoredPermissions.stream()
                .filter(scoredPermission -> scoredPermission.permission().getDecision() == decision)
                .findFirst();

        // 5. Final Scored Permission resolver
        return finalScoredPermission.map(scoredPermission ->
                        new PolicyEngineResult(scoredPermission.permission(), decision))
                .orElseGet(PolicyEngineResult::buildDefaultOutput);

    }

    private int getTopScoreOfPermissions(List<ScoredPermission> scoredPermissions){
        if(scoredPermissions == null || scoredPermissions.isEmpty()){
            return 0;
        }

        return scoredPermissions.stream()
                .mapToInt(ScoredPermission::score)
                .max()
                .orElse(Integer.MIN_VALUE);
    }
}