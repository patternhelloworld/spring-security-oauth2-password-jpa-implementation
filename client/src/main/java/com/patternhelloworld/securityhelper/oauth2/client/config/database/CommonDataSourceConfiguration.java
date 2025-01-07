package com.patternhelloworld.securityhelper.oauth2.client.config.database;

import com.zaxxer.hikari.HikariDataSource;
import jakarta.persistence.EntityManagerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;


@Configuration
@EnableJpaRepositories(
        basePackages = {"com.patternhelloworld.securityhelper.oauth2.client.domain",
                "com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl",
                "io.github.patternhelloworld.securityhelper.oauth2.api.config.security"},
        entityManagerFactoryRef = "commonEntityManagerFactory",
        transactionManagerRef= "commonTransactionManager"
)
public class CommonDataSourceConfiguration {

    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource.hikari.patternhelloworld")
    public DataSourceProperties commonDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean(name="commonDataSource")
    @Primary
    @ConfigurationProperties("spring.datasource.hikari.patternhelloworld.configuration")
    public DataSource commonDataSource() {
        return new LazyConnectionDataSourceProxy(commonDataSourceProperties().initializeDataSourceBuilder()
                .type(HikariDataSource.class).build());
    }

    @Primary
    @Bean(name = "commonEntityManagerFactory")
    public LocalContainerEntityManagerFactoryBean commonEntityManagerFactory(EntityManagerFactoryBuilder builder) {
        return builder
                .dataSource(commonDataSource())
                .packages("com.patternhelloworld.securityhelper.oauth2.client.domain",
                        "io.github.patternhelloworld.securityhelper.oauth2.api.config.security")
                .persistenceUnit("commonEntityManager")
                .build();
    }

    @Primary
    @Bean(name = "commonTransactionManager")
    public PlatformTransactionManager commonTransactionManager(@Qualifier("commonEntityManagerFactory") EntityManagerFactory entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory);
    }


}
