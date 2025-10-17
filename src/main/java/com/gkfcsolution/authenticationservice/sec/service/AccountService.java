package com.gkfcsolution.authenticationservice.sec.service;

import com.gkfcsolution.authenticationservice.sec.entities.AppRole;
import com.gkfcsolution.authenticationservice.sec.entities.AppUser;

import java.util.List;

/**
 * Created on 2025 at 10:35
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 10:35
 */

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
