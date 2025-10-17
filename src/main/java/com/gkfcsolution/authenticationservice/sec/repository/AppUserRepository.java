package com.gkfcsolution.authenticationservice.sec.repository;

import com.gkfcsolution.authenticationservice.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Created on 2025 at 10:33
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 10:33
 */
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
