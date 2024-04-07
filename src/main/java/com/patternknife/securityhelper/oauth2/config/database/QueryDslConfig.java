package com.patternknife.securityhelper.oauth2.config.database;


import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class QueryDslConfig {

    @PersistenceContext(unitName = "commonEntityManager")
    private EntityManager commonEntityManager;

    @Bean
    public JPAQueryFactory authJpaQueryFactory() {
        return new JPAQueryFactory(commonEntityManager);
    }

}
