package com.gkfcsolution.authenticationservice.sec.entities.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Created on 2025 at 14:53
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 14:53
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleUserForm {
    private String username;
    private String roleName;
}
