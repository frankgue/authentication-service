package com.gkfcsolution.authenticationservice.sec.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gkfcsolution.authenticationservice.sec.entities.AppRole;
import com.gkfcsolution.authenticationservice.sec.entities.AppUser;
import com.gkfcsolution.authenticationservice.sec.entities.dto.RoleUserForm;
import com.gkfcsolution.authenticationservice.sec.jwtUtilities.JWTUtil;
import com.gkfcsolution.authenticationservice.sec.service.AccountService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
@Slf4j
public class AccountRestController {
    private final AccountService accountService;
    @GetMapping(value = "/users")
    @PostAuthorize("hasRole('USER')")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping("/users")
    @PostAuthorize("hasRole('ADMIN')")
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

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authHeader = request.getHeader(JWTUtil.AUTH_HEADER);

        if (authHeader == null || !authHeader.startsWith(JWTUtil.BEARER_AUTH_HEADER_PREFIX)) {
            throw  new RemoteException("Resfresh token requis");
        }

        try {


        String token = authHeader.substring(JWTUtil.BEARER_AUTH_HEADER_PREFIX.length());
        String username = JWTUtil.extractUsername(token);
        log.info("Authorization header: {}", authHeader);
        log.info("Username from token: {}", username);

        // Si utilisateur trouvé
        AppUser appUser = accountService.loadUserByUsername(username);
        Key algorithKey = Keys.hmacShaKeyFor(JWTUtil.SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        // Génération du token JWT
        String jwtAccessToken = Jwts.builder()
                .setSubject(appUser.getUsername())
                .setIssuedAt(new Date())
                .claim("roles", appUser.getAppRoles().stream().map(role -> role.getRoleName()).collect(Collectors.toList()))
                .setExpiration(new Date(System.currentTimeMillis() + JWTUtil.ACCESS_TOKEN_EXPIRED_TIME_MS)) // 1 min
                .signWith(algorithKey, signatureAlgorithm)
                .compact();

        response.setHeader(JWTUtil.AUTH_HEADER, token);
        System.out.println("successfulAuthentication");


        // 🔁 Retourne le token dans la réponse JSON
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("username", appUser.getUsername());
        responseBody.put("access-token", jwtAccessToken);
        responseBody.put("refresh-token", token);
        responseBody.put("access-expiresIn", JWTUtil.ACCESS_TOKEN_EXPIRED_TIME_MS);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), responseBody);

        } catch (Exception e){
            throw e;
          /*  response.setHeader("Error-message", e.getMessage());
            response.sendError(HttpServletResponse.SC_FORBIDDEN);*/
        }

    }

    @GetMapping("/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }

}
