package com.example.TcgStoreMena;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping("")
    public ResponseEntity<Map<String, String>> getUser(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring("Bearer ".length());
        if (!JwtUtil.validateToken(token)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid JWT token"));
        }
        String email = JwtUtil.getEmailFromToken(token);
        Map<String, String> response = Map.ofEntries(
                Map.entry("email", email)
        );

        return new ResponseEntity<Map<String, String>>(response, HttpStatus.OK);
    }
}
