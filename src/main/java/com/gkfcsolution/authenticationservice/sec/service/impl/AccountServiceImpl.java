package com.gkfcsolution.authenticationservice.sec.service.impl;

import com.gkfcsolution.authenticationservice.sec.entities.AppRole;
import com.gkfcsolution.authenticationservice.sec.entities.AppUser;
import com.gkfcsolution.authenticationservice.sec.repository.AppRoleRepository;
import com.gkfcsolution.authenticationservice.sec.repository.AppUserRepository;
import com.gkfcsolution.authenticationservice.sec.service.AccountService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Created on 2025 at 11:26
 * File: AccountServiceImpl.java.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 11:26
 */
@Service
@Transactional
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {
    private final AppUserRepository userRepository;
    private final AppRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public AppUser addNewUser(AppUser appUser) {
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return userRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return roleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = userRepository.findByUsername(username);
        AppRole appRole = roleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> listUsers() {
        return userRepository.findAll();
    }
}
