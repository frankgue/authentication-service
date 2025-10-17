package com.gkfcsolution.authenticationservice.sec.repository;

import com.gkfcsolution.authenticationservice.sec.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Created on 2025 at 10:34
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 10:34
 */
public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRoleName(String roleName);
}
