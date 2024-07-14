package com.patternknife.securityhelper.oauth2.api.config.security.dao;

import com.patternknife.securityhelper.oauth2.api.config.security.entity.CustomOauthAccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface CustomOauthAccessTokenRepository extends JpaRepository<CustomOauthAccessToken, String> {

    List<CustomOauthAccessToken> findByClientIdAndUserName(String clientId, String username);


    Optional<CustomOauthAccessToken> findByTokenId(String tokenId);
    Optional<List<CustomOauthAccessToken>> findAllByTokenId(String tokenId);
    @Modifying
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    void deleteByTokenId(String tokenId);


    Optional<CustomOauthAccessToken> findByUserNameAndClientIdAndAppToken(String userName, String clientId, String appTokenValue);
    Optional<List<CustomOauthAccessToken>> findListByUserNameAndClientIdAndAppToken(String userName, String clientId, String appTokenValue);
    @Modifying
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    void deleteByUserNameAndClientIdAndAppToken(String userName, String clientId, String appTokenValue);



    @Modifying
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    void deleteByUserName(String username);


}