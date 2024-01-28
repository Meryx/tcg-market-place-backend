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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class UserRegistrationController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> createUser(@RequestBody UserRegistrationDto userRegistrationDto) {
        User user = userService.createUser(userRegistrationDto);
        Map<String, String> response = Map.ofEntries(
                Map.entry("message", "User created successfully"),
                Map.entry("statusCode", "200")
        );

        return new ResponseEntity<Map<String, String>>(response, HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto loginDto) {
        // Authenticate user (e.g., using username and password from loginRequest)
        // ...

        try {
            // Create JWT
            String jwtToken = createJwtToken();
            // Return JWT to the user
            return ResponseEntity.ok(jwtToken);
        } catch (JOSEException e) {
            System.out.println(e.toString());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error creating JWT");
        }
    }

    private String createJwtToken() throws JOSEException {
        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("Anwar")
                .issuer("your-issuer")
                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000)) // Set expiration time (e.g., 1 hour)
                .build();

        // Create a new signer using the secret key
        String secretKey = "do-you-believe-in-magic-in-a-young-girl-heart";
        JWSSigner signer = new MACSigner(secretKey.getBytes());

        // Create a new JWT
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        // Sign the JWT
        signedJWT.sign(signer);

        // Serialize to a compact form
        return signedJWT.serialize();
    }
}
