package io.github.patternknife.securityhelper.oauth2.api.config.security.dao;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeAuthorization;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface KnifeAuthorizationRepository extends JpaRepository<KnifeAuthorization, String> {

    /*
    *  [1] From "https://github.com/spring-projects/spring-authorization-server/tree/main/docs/src/main/java/sample/jpa"
    * */
    Optional<KnifeAuthorization> findByState(String state);
    Optional<KnifeAuthorization> findByAuthorizationCodeValue(String authorizationCode);
    Optional<KnifeAuthorization> findByAccessTokenValue(String accessToken);
    Optional<KnifeAuthorization> findByRefreshTokenValue(String refreshToken);
    Optional<KnifeAuthorization> findByOidcIdTokenValue(String idToken);
    Optional<KnifeAuthorization> findByUserCodeValue(String userCode);
    Optional<KnifeAuthorization> findByDeviceCodeValue(String deviceCode);

    @Query("select a from KnifeAuthorization a where a.state = :token" +
            " or a.authorizationCodeValue = :token" +
            " or a.accessTokenValue = :token" +
            " or a.refreshTokenValue = :token" +
            " or a.oidcIdTokenValue = :token" +
            " or a.userCodeValue = :token" +
            " or a.deviceCodeValue = :token"
    )
    Optional<KnifeAuthorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);

    @Transactional
    @Modifying
    void deleteByState(String state);
    @Transactional
    @Modifying
    void deleteByAuthorizationCodeValue(String authorizationCode);
    @Transactional
    @Modifying
    void deleteByAccessTokenValue(String accessToken);
    @Transactional
    @Modifying
    void deleteByRefreshTokenValue(String refreshToken);
    @Transactional
    @Modifying
    void deleteByOidcIdTokenValue(String idToken);
    @Transactional
    @Modifying
    void deleteByUserCodeValue(String userCode);
    @Transactional
    @Modifying
    void deleteByDeviceCodeValue(String deviceCode);

    @Transactional
    @Query("DELETE FROM KnifeAuthorization a WHERE a.state = :token OR " +
            "a.authorizationCodeValue = :token OR " +
            "a.accessTokenValue = :token OR " +
            "a.refreshTokenValue = :token OR " +
            "a.oidcIdTokenValue = :token OR " +
            "a.userCodeValue = :token OR " +
            "a.deviceCodeValue = :token")
    @Modifying
    void deleteAllByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);


    /*
     *  [2] From "Knife"
     *      : Spring Security 5 -> 6
     *          : clientId -> registeredClientId, userName -> principalName
     * */

    List<KnifeAuthorization> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String username);

    /*
    *   tokenId -> id
    * */
    Optional<KnifeAuthorization> findById(String id);
    Optional<List<KnifeAuthorization>> findAllById(String id);

    @Modifying
    @Transactional(rollbackFor=Exception.class)
    void deleteById(String id);


    Optional<KnifeAuthorization> findByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(String principalName, String registeredClientId, String accessTokenAppToken);
    Optional<List<KnifeAuthorization>> findListByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(String principalName, String registeredClientId, String accessTokenAppToken);
    @Modifying
    @Transactional(rollbackFor=Exception.class)
    void deleteByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(String principalName, String registeredClientId, String accessTokenAppToken);

    @Modifying
    @Transactional(rollbackFor=Exception.class)
    void deleteByPrincipalName(String principalName);

}
