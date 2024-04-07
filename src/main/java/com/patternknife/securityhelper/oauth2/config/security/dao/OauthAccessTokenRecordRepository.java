package com.patternknife.securityhelper.oauth2.config.security.dao;

import com.patternknife.securityhelper.oauth2.config.security.entity.OauthAccessTokenRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface OauthAccessTokenRecordRepository extends JpaRepository<OauthAccessTokenRecord, OauthAccessTokenRecord.OAuthAccessTokenUserAgentRecordId> {


}