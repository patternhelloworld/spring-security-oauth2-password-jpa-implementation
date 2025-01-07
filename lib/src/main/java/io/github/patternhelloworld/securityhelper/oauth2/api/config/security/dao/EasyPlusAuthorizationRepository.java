package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusAuthorization;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface EasyPlusAuthorizationRepository extends JpaRepository<EasyPlusAuthorization, String> {

    /*
    *  [1] From "https://github.com/spring-projects/spring-authorization-server/tree/main/docs/src/main/java/sample/jpa"
    * */
    Optional<EasyPlusAuthorization> findByState(String state);
    Optional<EasyPlusAuthorization> findByAuthorizationCodeValue(String authorizationCode);
    Optional<EasyPlusAuthorization> findByAccessTokenValue(String accessToken);
    Optional<EasyPlusAuthorization> findByRefreshTokenValue(String refreshToken);
    Optional<EasyPlusAuthorization> findByOidcIdTokenValue(String idToken);
    Optional<EasyPlusAuthorization> findByUserCodeValue(String userCode);
    Optional<EasyPlusAuthorization> findByDeviceCodeValue(String deviceCode);

    @Query("select a from EasyPlusAuthorization a where a.state = :token" +
            " or a.authorizationCodeValue = :token" +
            " or a.accessTokenValue = :token" +
            " or a.refreshTokenValue = :token" +
            " or a.oidcIdTokenValue = :token" +
            " or a.userCodeValue = :token" +
            " or a.deviceCodeValue = :token"
    )
    Optional<EasyPlusAuthorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);

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
    @Query("DELETE FROM EasyPlusAuthorization a WHERE a.state = :token OR " +
            "a.authorizationCodeValue = :token OR " +
            "a.accessTokenValue = :token OR " +
            "a.refreshTokenValue = :token OR " +
            "a.oidcIdTokenValue = :token OR " +
            "a.userCodeValue = :token OR " +
            "a.deviceCodeValue = :token")
    @Modifying
    void deleteAllByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);


    /*
     *  [2] From "EasyPlus"
     *      : Spring Security 5 -> 6
     *          : clientId -> registeredClientId, userName -> principalName
     * */

    List<EasyPlusAuthorization> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String username);

    /*
    *   tokenId -> id
    * */
    Optional<EasyPlusAuthorization> findById(String id);
    Optional<List<EasyPlusAuthorization>> findAllById(String id);

    @Modifying
    @Transactional(rollbackFor=Exception.class)
    void deleteById(String id);


    Optional<EasyPlusAuthorization> findByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(String principalName, String registeredClientId, String accessTokenAppToken);

    @Query("SELECT o FROM EasyPlusAuthorization o WHERE o.principalName = :principalName AND o.registeredClientId = :registeredClientId AND o.accessTokenAppToken = :accessTokenAppToken AND o.accessTokenExpiresAt > CURRENT_TIMESTAMP")
    Optional<EasyPlusAuthorization> findValidAuthorizationByPrincipalNameAndClientIdAndAppToken(
            @Param("principalName") String principalName,
            @Param("registeredClientId") String registeredClientId,
            @Param("accessTokenAppToken") String accessTokenAppToken
    );

    @Query("SELECT o FROM EasyPlusAuthorization o WHERE o.principalName = :principalName AND o.registeredClientId = :registeredClientId AND " +
            "(o.accessTokenAppToken = :accessTokenAppToken OR (o.accessTokenAppToken IS NULL AND :accessTokenAppToken IS NULL)) " +
            "AND o.accessTokenExpiresAt > CURRENT_TIMESTAMP")
    Optional<EasyPlusAuthorization> findValidAuthorizationByPrincipalNameAndClientIdAndNullableAppToken(
            @Param("principalName") String principalName,
            @Param("registeredClientId") String registeredClientId,
            @Param("accessTokenAppToken") String accessTokenAppToken
    );



    Optional<List<EasyPlusAuthorization>> findListByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(String principalName, String registeredClientId, String accessTokenAppToken);
    @Modifying
    @Transactional(rollbackFor=Exception.class)
    void deleteByPrincipalNameAndRegisteredClientIdAndAccessTokenAppToken(String principalName, String registeredClientId, String accessTokenAppToken);

    @Modifying
    @Transactional(rollbackFor=Exception.class)
    void deleteByPrincipalName(String principalName);

}
