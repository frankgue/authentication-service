package com.gkfcsolution.authenticationservice.sec.entities.dto;

import lombok.*;

/**
 * Created on 2025 at 22:15
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 22:15
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    private String username;
    private String password;
}
