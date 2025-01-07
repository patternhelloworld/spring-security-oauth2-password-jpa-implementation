package com.patternhelloworld.securityhelper.oauth2.client.domain.role.dao;

import com.patternhelloworld.securityhelper.oauth2.client.domain.role.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;


public interface RoleRepository extends JpaRepository<Role, Long> {

}