package io.github.patternknife.securityhelper.oauth2.api.config.security.dao;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthAccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface KnifeOauthAccessTokenRepository extends JpaRepository<KnifeOauthAccessToken, String> {

    List<KnifeOauthAccessToken> findByClientIdAndUserName(String clientId, String username);


    Optional<KnifeOauthAccessToken> findByTokenId(String tokenId);
    Optional<List<KnifeOauthAccessToken>> findAllByTokenId(String tokenId);
    @Modifying
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    void deleteByTokenId(String tokenId);


    Optional<KnifeOauthAccessToken> findByUserNameAndClientIdAndAppToken(String userName, String clientId, String appTokenValue);
    Optional<List<KnifeOauthAccessToken>> findListByUserNameAndClientIdAndAppToken(String userName, String clientId, String appTokenValue);
    @Modifying
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    void deleteByUserNameAndClientIdAndAppToken(String userName, String clientId, String appTokenValue);



    @Modifying
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    void deleteByUserName(String username);


}