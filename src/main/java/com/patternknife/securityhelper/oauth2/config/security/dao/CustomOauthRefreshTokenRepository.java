package com.patternknife.securityhelper.oauth2.config.security.dao;

import com.patternknife.securityhelper.oauth2.config.security.entity.CustomOauthRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;


public interface CustomOauthRefreshTokenRepository extends JpaRepository<CustomOauthRefreshToken, String> {

    Optional<CustomOauthRefreshToken> findByTokenId(String s);
    Optional<List<CustomOauthRefreshToken>> findAllByTokenId(String tokenId);

    @Modifying
    @Transactional(value = "commonTransactionManager", rollbackFor=Exception.class)
    void deleteByTokenId(String tokenId);

}