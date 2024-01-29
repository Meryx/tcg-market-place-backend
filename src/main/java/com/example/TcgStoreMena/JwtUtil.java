package com.example.TcgStoreMena;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JwtUtil {

    private static final String SECRET_KEY = System.getenv("JWT_SECRET_KEY"); // Replace with your actual key string

    private static final SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)); // Replace with your actual key

    public static boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
