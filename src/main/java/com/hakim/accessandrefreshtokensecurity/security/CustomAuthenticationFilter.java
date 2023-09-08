package com.hakim.accessandrefreshtokensecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hakim.accessandrefreshtokensecurity.model.User;
import com.hakim.accessandrefreshtokensecurity.utility.JwtHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationProvider authenticationProvider;

    public CustomAuthenticationFilter(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // Extract the username and password from request attribute
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Create instance of UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // Authenticate the user
        return authenticationProvider.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        // Extract the authenticated user.
        User user = (User) authentication.getPrincipal();

        // Generate access and refresh tokens
        String accessToken = JwtHelper.generateToken(user, (1000L * 60 * 60 * 24 * 7)); // expires in 7 days
        String refreshToken = JwtHelper.generateToken(user, (1000L * 60 * 60 * 24 * 30)); // expires in 30 days

        Map<String,String> tokenMap = new HashMap<>();
        tokenMap.put("access-token",accessToken);
        tokenMap.put("refresh-token",refreshToken);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(),tokenMap);
    }
}
