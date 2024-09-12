package com.products.UserMicroService.jwt;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;

@Component
public class JWTUtils {

    private static final Logger logger = LoggerFactory.getLogger(JWTUtils.class);

    @Value("${spring.app.jwtsecret}")
    private String mySecretKey;

    @Value("${spring.app.jwt-token-expiry}")
    private int myJwtExpiresIn;

    public String getJWTFromHeader(HttpServletRequest request) {

        String header = request.getHeader("Authorization");
        logger.debug("Request Header token {}",header);
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        return header.substring(7);
    }

    public String generateToken(UserDetails userDetails) {

        String username = userDetails.getUsername();
        return Jwts.builder().setSubject(username).setIssuedAt(new Date())
                .expiration(new Date(new Date().getTime()+myJwtExpiresIn)).
                signWith(getMySecretKey()).compact();
    }

    public Key getMySecretKey() {
        /*KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        SecretKey key = keyGen.generateKey();
        String secKey = Base64.getEncoder().encodeToString(key.getEncoded());
        byte[] keyBytes = Decoders.BASE64.decode(secKey);
        return Keys.hmacShaKeyFor(keyBytes); */
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(mySecretKey));
    }

    public boolean validateToken(String token) {

        try{
            Jwts.parser().verifyWith((SecretKey) getMySecretKey()).build().parseSignedClaims(token);
            return true;
        }
        catch (MalformedJwtException e) {
            logger.debug("Invalid jwt token {}"+e.getMessage());
        }
        catch (ExpiredJwtException e) {
            logger.debug("Expired jwt token {}"+e.getMessage());
        }
        catch (UnsupportedJwtException e) {
            logger.debug("Unsupported jwt token {}"+e.getMessage());
        }
        catch (IllegalArgumentException e) {
            logger.debug("JWT claims string is empty {}"+e.getMessage());
        }
        return false;
    }

    public String getUsernameFromJwtToken(String token) {

        return Jwts.parser().verifyWith((SecretKey) getMySecretKey()).build().
                parseSignedClaims(token).getPayload().getSubject();
    }
}
