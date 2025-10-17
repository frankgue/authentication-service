package com.gkfcsolution.authenticationservice.sec.controller;

import com.gkfcsolution.authenticationservice.sec.entities.AppRole;
import com.gkfcsolution.authenticationservice.sec.entities.AppUser;
import com.gkfcsolution.authenticationservice.sec.entities.dto.RoleUserForm;
import com.gkfcsolution.authenticationservice.sec.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Created on 2025 at 13:24
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 13:24
 */
@RestController
@RequiredArgsConstructor
public class AccountRestController {
    private final AccountService accountService;

    @GetMapping(value = "/users")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping("/users")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping("/roles")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(value = "/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }

}
