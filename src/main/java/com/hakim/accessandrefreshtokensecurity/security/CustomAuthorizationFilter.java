package com.hakim.accessandrefreshtokensecurity.security;

import com.hakim.accessandrefreshtokensecurity.service.CustomUserDetailsService;
import com.hakim.accessandrefreshtokensecurity.utility.JwtHelper;
import com.hakim.accessandrefreshtokensecurity.utility.ResponseUtility;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // If this is request is for login, Simply let the request go.
        if (request.getServletPath().equalsIgnoreCase("/login") || request.getServletPath().equalsIgnoreCase("/refreshToken")) {
            filterChain.doFilter(request, response);
        } else {

            String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (authorization != null && authorization.startsWith("Bearer ")) {
                try {
                    // Extract the token from authorization text
                    String token = authorization.substring("Bearer ".length());

                    // Extract the username
                    String username = JwtHelper.extractUsername(token);

                    Object roles = JwtHelper.extractClaim(token, "roles");
                    System.out.println(roles);

                    // Get the userDetails using username
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    // If the token is valid and user is not authenticated, authenticate the user
                    if (JwtHelper.isValidToken(token, userDetails) && SecurityContextHolder.getContext().getAuthentication() == null) {
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                userDetails.getPassword(),
                                userDetails.getAuthorities() // We need to pass the Granted Authority list, otherwise user would be forbidden.
                        );
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }
                } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException ex) {

                    // If the token is Invalid send an error with the response
                    Map<String, String> errorMap = new HashMap<>();
                    errorMap.put("error", "Invalid Token");
                    ResponseUtility.commitResponse(response,errorMap);
                }
            }

            // If the authorization does not exist, or it does not start with Bearer, simply let the program go.
            filterChain.doFilter(request, response);
        }
    }
}
