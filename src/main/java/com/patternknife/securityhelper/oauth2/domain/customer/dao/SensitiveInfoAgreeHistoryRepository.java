package com.patternknife.securityhelper.oauth2.domain.customer.dao;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.SensitiveInfoAgreeHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;

public interface SensitiveInfoAgreeHistoryRepository extends JpaRepository<SensitiveInfoAgreeHistory, Long>, QuerydslPredicateExecutor<SensitiveInfoAgreeHistory> {
}