package io.github.patternknife.securityhelper.oauth2.api.config.security.dao;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeOauthRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface KnifeOauthRefreshTokenRepository extends JpaRepository<KnifeOauthRefreshToken, String> {

    Optional<KnifeOauthRefreshToken> findByTokenId(String s);
    Optional<List<KnifeOauthRefreshToken>> findAllByTokenId(String tokenId);

    @Modifying
    @Transactional( rollbackFor=Exception.class)
    void deleteByTokenId(String tokenId);

}