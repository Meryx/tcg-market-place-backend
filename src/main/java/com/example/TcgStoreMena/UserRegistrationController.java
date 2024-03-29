package com.example.TcgStoreMena;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/auth")
public class UserRegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> createUser(@RequestBody UserRegistrationDto userRegistrationDto) {
        if(userService.findByEmail(userRegistrationDto.getEmail()) != null)
        {
            Map<String, String> response = Map.ofEntries(
                    Map.entry("message", "Email already exists"),
                    Map.entry("statusCode", "400")
            );

            return new ResponseEntity<Map<String, String>>(response, HttpStatus.BAD_REQUEST);
        }

        String password = userRegistrationDto.getPassword();
        String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z\\d]).{8,}$";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(password);
        boolean matches = matcher.matches();

        if(!matches)
        {
            Map<String, String> response = Map.ofEntries(
                    Map.entry("message", "Weak password"),
                    Map.entry("statusCode", "400")
            );

            return new ResponseEntity<Map<String, String>>(response, HttpStatus.BAD_REQUEST);
        }

        String email = userRegistrationDto.getEmail();
        regex = "(?:[a-zA-Z0-9_'^&/+-]+(?:\\.[a-zA-Z0-9_'^&/+-]+)*|\"[^(\\\\|\")]*\")@(?:[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*\\.[a-zA-Z]{2,})";

        pattern = Pattern.compile(regex);
        matcher = pattern.matcher(email);
        matches = matcher.matches();

        if(!matches)
        {
            Map<String, String> response = Map.ofEntries(
                    Map.entry("message", "Not a valid email address"),
                    Map.entry("statusCode", "400")
            );
            return new ResponseEntity<Map<String, String>>(response, HttpStatus.BAD_REQUEST);
        }

        User user = userService.createUser(userRegistrationDto);
        Map<String, String> response = Map.ofEntries(
                Map.entry("message", "User created successfully"),
                Map.entry("statusCode", "200")
        );

        return new ResponseEntity<Map<String, String>>(response, HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginDto loginDto) {

        String email = loginDto.getEmail();
        String password = loginDto.getPassword();



        User user = userService.findByEmail(email);

        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            try {
                String jwtToken = createJwtToken(email);
                Map<String, String> response = Map.ofEntries(
                        Map.entry("message", "User logged-in successfully"),
                        Map.entry("statusCode", "200"),
                        Map.entry("JWT", jwtToken)
                );
                return new ResponseEntity<Map<String, String>>(response, HttpStatus.OK);
            } catch (Exception e) {
                Map<String, String> response = Map.ofEntries(
                        Map.entry("message", e.toString()),
                        Map.entry("statusCode", "500")
                );
                return new ResponseEntity<Map<String, String>>(response, HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } else {
            Map<String, String> response = Map.ofEntries(
                    Map.entry("message", "Invalid email or password"),
                    Map.entry("statusCode", "401")
            );
            return new ResponseEntity<Map<String, String>>(response, HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Boolean> authenticate(@RequestBody String jwtToken) {
        boolean isValid = JwtUtil.validateToken(jwtToken);
        return ResponseEntity.ok(isValid);
    }

    private String createJwtToken(String email) throws JOSEException {
        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(email)
                .issuer("tcg-backend")
                .expirationTime(new Date(System.currentTimeMillis() + 604800 * 1000)) // Set expiration time (e.g., 1 hour)
                .build();

        // Create a new signer using the secret key
        String secretKey = System.getenv("JWT_SECRET_KEY");
        JWSSigner signer = new MACSigner(secretKey.getBytes());

        // Create a new JWT
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        // Sign the JWT
        signedJWT.sign(signer);

        // Serialize to a compact form
        return signedJWT.serialize();
    }


}
