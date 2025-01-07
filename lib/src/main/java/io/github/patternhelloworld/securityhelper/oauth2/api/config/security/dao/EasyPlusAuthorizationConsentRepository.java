package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusAuthorizationConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EasyPlusAuthorizationConsentRepository extends JpaRepository<EasyPlusAuthorizationConsent, EasyPlusAuthorizationConsent.AuthorizationConsentId> {
    Optional<EasyPlusAuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}