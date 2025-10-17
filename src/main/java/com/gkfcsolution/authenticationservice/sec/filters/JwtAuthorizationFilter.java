package com.gkfcsolution.authenticationservice.sec.filters;

import com.gkfcsolution.authenticationservice.sec.jwtUtilities.JWTUtil;
import com.gkfcsolution.authenticationservice.sec.service.impl.CustomUserDetailsServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

/**
 * Created on 2025 at 22:53
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 16/10/2025
 * @time 22:53
 */

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final CustomUserDetailsServiceImpl userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader(JWTUtil.AUTH_HEADER);


        if (authHeader == null || !authHeader.startsWith(JWTUtil.BEARER_AUTH_HEADER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(JWTUtil.BEARER_AUTH_HEADER_PREFIX.length());
        String username = JWTUtil.extractUsername(token);
        log.info("Authorization header: {}", authHeader);
        log.info("Username from token: {}", username);
        // 🔎 Si utilisateur trouvé et non déjà authentifié

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (JWTUtil.validateToken(token, userDetails)){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        filterChain.doFilter(request,response);
    }

}
