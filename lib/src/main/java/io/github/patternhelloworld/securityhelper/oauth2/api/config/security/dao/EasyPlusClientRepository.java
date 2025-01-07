package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.dao;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.entity.EasyPlusClient;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EasyPlusClientRepository extends JpaRepository<EasyPlusClient, String> {
    /*
     *  [1] From "https://github.com/spring-projects/spring-authorization-server/tree/main/docs/src/main/java/sample/jpa"
     * */
    Optional<EasyPlusClient> findByClientId(String clientId);

    /*
     *  [2] From "EasyPlus"
     *      : Spring Security 5 -> 6
     * */

}
