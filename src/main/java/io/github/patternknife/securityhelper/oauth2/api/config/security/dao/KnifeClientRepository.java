package io.github.patternknife.securityhelper.oauth2.api.config.security.dao;

import io.github.patternknife.securityhelper.oauth2.api.config.security.entity.KnifeClient;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KnifeClientRepository extends JpaRepository<KnifeClient, String> {
    /*
     *  [1] From "https://github.com/spring-projects/spring-authorization-server/tree/main/docs/src/main/java/sample/jpa"
     * */
    Optional<KnifeClient> findByClientId(String clientId);

    /*
     *  [2] From "Knife"
     *      : Spring Security 5 -> 6
     * */

}
