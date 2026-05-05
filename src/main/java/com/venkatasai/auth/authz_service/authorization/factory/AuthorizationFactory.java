package com.venkatasai.auth.authz_service.authorization.factory;

import com.venkatasai.auth.authz_service.authorization.strategy.AuthorizationStrategy;
import com.venkatasai.auth.authz_service.exception.AuthorizationException;
import com.venkatasai.auth.authz_service.model.AuthorizationType;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class AuthorizationFactory {

    private final Map<AuthorizationType, AuthorizationStrategy> strategyMap;

    /**
     * Spring injects all AuthorizationStrategy beans as a list.
     * Each strategy self-declares its type via getType(), so no manual
     * map construction is needed in AppConfig.
     */
    public AuthorizationFactory(List<AuthorizationStrategy> strategies) {
        this.strategyMap = strategies.stream()
                .collect(Collectors.toMap(AuthorizationStrategy::getType, Function.identity()));
    }

    public AuthorizationStrategy getAuthorizationStrategy(AuthorizationType authorizationType) {
        AuthorizationStrategy strategy = strategyMap.get(authorizationType);

        if (strategy == null) {
            throw new AuthorizationException("Unsupported authorization type: " + authorizationType);
        }

        return strategy;
    }
}