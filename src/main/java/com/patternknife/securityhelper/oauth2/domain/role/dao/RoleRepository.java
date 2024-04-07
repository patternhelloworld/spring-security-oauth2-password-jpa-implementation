package com.patternknife.securityhelper.oauth2.domain.role.dao;

import com.patternknife.securityhelper.oauth2.domain.role.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;


public interface RoleRepository extends JpaRepository<Role, Long> {

}