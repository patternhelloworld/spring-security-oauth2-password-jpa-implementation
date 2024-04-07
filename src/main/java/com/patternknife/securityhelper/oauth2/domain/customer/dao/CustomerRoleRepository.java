package com.patternknife.securityhelper.oauth2.domain.customer.dao;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.CustomerRole;
import org.springframework.data.jpa.repository.JpaRepository;


public interface CustomerRoleRepository extends JpaRepository<CustomerRole, Long> {

}
