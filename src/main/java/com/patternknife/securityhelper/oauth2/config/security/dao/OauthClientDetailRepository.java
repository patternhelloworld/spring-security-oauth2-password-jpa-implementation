package com.patternknife.securityhelper.oauth2.config.security.dao;

import com.patternknife.securityhelper.oauth2.config.security.entity.OauthClientDetail;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface OauthClientDetailRepository extends JpaRepository<OauthClientDetail, String> {

    Optional<OauthClientDetail> findByClientIdAndResourceIds(String clientId, String resourceIds);

}