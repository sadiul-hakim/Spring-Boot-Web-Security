package com.hakim.accessandrefreshtokensecurity.utility;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtHelper {
    private static final String SECRET = "VxRfBGJFviiO62cg/M0YY5WypcyvtUUjfkI5aDJgwt4dLz6BQKuaKChKyn+Ulhz+";

    public String generateToken(UserDetails userDetails) {

        Map<String, Object> extraClaims = new HashMap<>();
        return generateToken(userDetails,extraClaims);
    }

    private String generateToken(UserDetails userDetails, Map<String, Object> extraClaims) {

        return Jwts.builder()
                .setClaims(extraClaims)
                .signWith(getSecretKey(),SignatureAlgorithm.HS256)
                .setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24 * 7)))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setSubject(userDetails.getUsername())
                .compact();
    }

    public boolean isValidToken(String token, UserDetails details) {
        return extractUsername(token).equalsIgnoreCase(details.getUsername()) && !isExpired(token);
    }

    private boolean isExpired(String token) {

        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {

        return parseSingleClaim(token, Claims::getExpiration);
    }

    public String extractUsername(String token) {

        return parseSingleClaim(token, Claims::getSubject);
    }

    private <T> T parseSingleClaim(String token, Function<Claims, T> resolver) {

        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(getSecretKey()).build();
        return parser.parseClaimsJws(token).getBody();
    }

    private Key getSecretKey() {

        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }
}
