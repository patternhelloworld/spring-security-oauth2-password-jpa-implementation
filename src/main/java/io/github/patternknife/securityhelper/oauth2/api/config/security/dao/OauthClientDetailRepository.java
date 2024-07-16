package io.github.patternknife.securityhelper.oauth2.api.config.security.dao;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.OauthClientDetail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OauthClientDetailRepository extends JpaRepository<OauthClientDetail, String> {

    Optional<OauthClientDetail> findByClientIdAndResourceIds(String clientId, String resourceIds);

}