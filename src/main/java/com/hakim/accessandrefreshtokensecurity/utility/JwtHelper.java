package com.hakim.accessandrefreshtokensecurity.utility;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

public class JwtHelper {
    private static final String SECRET = "VxRfBGJFviiO62cg/M0YY5WypcyvtUUjfkI5aDJgwt4dLz6BQKuaKChKyn+Ulhz+";


    public static String generateToken(UserDetails userDetails, Map<String, Object> extraClaims, long expirationDate) {

        return Jwts.builder()
                .setClaims(extraClaims)
                .signWith(getSecretKey(), SignatureAlgorithm.HS256)
                .setExpiration(new Date(System.currentTimeMillis() + expirationDate))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setSubject(userDetails.getUsername())
                .compact();
    }

    public static boolean isValidToken(String token, UserDetails details) throws MalformedJwtException{

        boolean isValid = extractUsername(token).equalsIgnoreCase(details.getUsername()) && !isExpired(token);
        if(!isValid){
            throw new MalformedJwtException("Invalid Token");
        }
        return true;
    }

    private static boolean isExpired(String token) {

        return extractExpiration(token).before(new Date());
    }

    private static Date extractExpiration(String token) throws MalformedJwtException {

        return parseSingleClaim(token, Claims::getExpiration);
    }

    public static String extractUsername(String token) throws MalformedJwtException {

        return parseSingleClaim(token, Claims::getSubject);
    }

    public static Object extractClaim(String token,String claim) throws MalformedJwtException {

        return parseSingleClaim(token, claims -> claims.get(claim, Object.class));
    }

    private static  <T> T parseSingleClaim(String token, Function<Claims, T> resolver) throws MalformedJwtException {

        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private static Claims extractAllClaims(String token) throws MalformedJwtException {

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(getSecretKey()).build();
        return parser.parseClaimsJws(token).getBody();
    }

    private static Key getSecretKey() {

        byte[] bytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(bytes);
    }
}
