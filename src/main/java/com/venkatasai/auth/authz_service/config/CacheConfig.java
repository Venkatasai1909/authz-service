package com.venkatasai.auth.authz_service.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfig {

    @Value("${cache.permissions.max-size:1000}")
    private int maxSize;

    @Value("${cache.permissions.expire-after-write-minutes:5}")
    private int expireAfterWriteMinutes;

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager("permissions");
        manager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(maxSize)
                .expireAfterWrite(expireAfterWriteMinutes, TimeUnit.MINUTES)
                .recordStats());
        return manager;
    }
}