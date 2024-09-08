package com.github.patternknife.securityhelper.oauth2.api.config.security.dao;

import com.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthClientDetail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface KnifeOauthClientDetailRepository extends JpaRepository<KnifeOauthClientDetail, String> {

    Optional<KnifeOauthClientDetail> findByClientIdAndResourceIds(String clientId, String resourceIds);

}