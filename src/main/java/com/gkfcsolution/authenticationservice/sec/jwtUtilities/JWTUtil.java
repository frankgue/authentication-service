package com.gkfcsolution.authenticationservice.sec.jwtUtilities;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

/**
 * Created on 2025 at 17:03
 * File: null.java
 * Project: authentication-service
 *
 * @author Frank GUEKENG
 * @date 17/10/2025
 * @time 17:03
 */
@Slf4j
public class JWTUtil {

    public static final String SECRET_KEY = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    public static final String AUTH_HEADER = "Authorization";
    public static final String BEARER_AUTH_HEADER_PREFIX = "Bearer ";
    public static final long ACCESS_TOKEN_EXPIRED_TIME_MS = 2 * 60 * 1000; // 1 min
    // public static final long ACCESS_TOKEN_EXPIRED_TIME_MS = 10 * 60 * 60 * 1000; // 10h
    public static final long REFRESH_TOKEN_EXPIRED_TIME_MS = 10 * 60 * 1000; // 10 min
//  public static final long REFRESH_TOKEN_EXPIRED_TIME_MS = 10 * 60 * 60 * 1000; // 10h


    // 🔐 Clé secrète JWT (à externaliser dans application.yml pour la production)
    //    @Value("${jwt.secret-key}")
    //    private String SECRET_KEY;





    // 🧠 Extraction du username à partir du token
    public static String extractUsername(String token){
        try {
            Claims claims = extractAllClaims(token);
            return claims.getSubject();
        } catch (Exception e){
            log.error("Invalid JWT: {}", e.getMessage());
            return null;
        }
    }

    // ⚙️ Lecture et parsing du JWT
    public static Claims extractAllClaims(String token){
        Key key = Keys.hmacShaKeyFor(JWTUtil.SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ✅ Validation du token
    public static boolean validateToken(String token, UserDetails userDetails){
        String username = extractUsername(token);
        return username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public static boolean isTokenExpired(String token){
        Claims claims = extractAllClaims(token);
        return claims.getExpiration().before(new Date());
    }
}
