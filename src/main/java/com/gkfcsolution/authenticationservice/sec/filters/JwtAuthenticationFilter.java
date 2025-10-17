package com.gkfcsolution.authenticationservice.sec.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gkfcsolution.authenticationservice.sec.entities.dto.LoginRequest;
import com.gkfcsolution.authenticationservice.sec.jwtUtilities.JWTUtil;
import com.gkfcsolution.authenticationservice.sec.service.impl.CustomUserDetailsImpl;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created on 2025 at 16:23
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 16:23
 */


/**
 * JWT Authentication Filter
 * - Authentifie l'utilisateur via /login
 * - Génère un JWT si succès
 */

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {
        try {
            System.out.println("attemptAuthentication");
            // Lecture du JSON envoyé (username + password)
            String contentType = request.getContentType();
            String username;
            String password;
            if (contentType != null && contentType.contains("application/json")) {
                LoginRequest loginRequest = new ObjectMapper()
                        .readValue(request.getInputStream(), LoginRequest.class);
                username = loginRequest.getUsername();
                password = loginRequest.getPassword();
            } else {
                username = request.getParameter("username");
                password = request.getParameter("password");
            }

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

            return authenticationManager.authenticate(authenticationToken);

        } catch (IOException e) {

            throw new RuntimeException("Erreur lors de la lecture des identifiants", e);
        }
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        CustomUserDetailsImpl user = (CustomUserDetailsImpl) authResult.getPrincipal();
        Key algorithKey = Keys.hmacShaKeyFor(JWTUtil.SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        // Génération du token JWT
        String token = Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .claim("roles", user.getAuthorities().stream().map(grantedAuthority -> grantedAuthority.getAuthority()).collect(Collectors.toList()))
                .setExpiration(new Date(System.currentTimeMillis() + JWTUtil.ACCESS_TOKEN_EXPIRED_TIME_MS)) // 1 min
                .signWith(algorithKey, signatureAlgorithm)
                .compact();

        // Génération du refres token JWT
        String refreshToken = Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
//                .claim("roles", user.getAuthorities().stream().map(grantedAuthority -> grantedAuthority.getAuthority()).collect(Collectors.toList()))
                .setExpiration(new Date(System.currentTimeMillis() + JWTUtil.REFRESH_TOKEN_EXPIRED_TIME_MS)) // 15 min
                .signWith(Keys.hmacShaKeyFor(JWTUtil.SECRET_KEY.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
        response.setHeader(JWTUtil.AUTH_HEADER, token);
        System.out.println("successfulAuthentication");


        // 🔁 Retourne le token dans la réponse JSON
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("username", user.getUsername());
        responseBody.put("access-token", token);
        responseBody.put("refresh-token", refreshToken);
        responseBody.put("access-expiresIn", JWTUtil.ACCESS_TOKEN_EXPIRED_TIME_MS);
        responseBody.put("refresh-token-expiresIn", JWTUtil.REFRESH_TOKEN_EXPIRED_TIME_MS);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), responseBody);

    }


    @Override
    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }
}
