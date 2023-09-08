package com.hakim.accessandrefreshtokensecurity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hakim.accessandrefreshtokensecurity.utility.JwtHelper;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class RefreshTokenController {
    private final UserDetailsService userDetailsService;
    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Bearer ")) {
            try {
                // Extract the token from authorization text
                String token = authorization.substring("Bearer ".length());

                // Extract the username
                String username = JwtHelper.extractUsername(token);

                // Get the userDetails using username
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // If the token is valid generate a new access token and send it to user.
                if (JwtHelper.isValidToken(token, userDetails)) {

                    String accessToken = JwtHelper.generateToken(userDetails, (1000 * 60 * 60 * 24 * 7));
                    Map<String, String> tokenMap = new HashMap<>();
                    tokenMap.put("access-token", accessToken);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), tokenMap);
                }
            } catch (MalformedJwtException | IOException ex) {

                // If the token is Invalid send an error with the response
                Map<String, String> tokenMap = new HashMap<>();
                tokenMap.put("error", "Invalid Token");
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokenMap);
            }
        } else {
            throw new RuntimeException("Refresh token is missing.");
        }
    }
}
