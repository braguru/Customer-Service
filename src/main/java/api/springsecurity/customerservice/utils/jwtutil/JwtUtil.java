package api.springsecurity.customerservice.utils.jwtutil;

import api.springsecurity.customerservice.entity.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;

/**
 * Service implementation for handling JWT (JSON Web Token) operations.
 * <p>
 * This service includes functionality for generating JWT tokens, extracting user claims
 * (such as email, phone, and username), and validating tokens against user details.
 * The tokens are signed using a secret key for security.
 */
@Component
@RequiredArgsConstructor
public class JwtUtil {

    @Value("${JWT_SECRET}")
    private String secret;

    private static final long TOKEN_VALIDITY = 1000 * 60 * 60L; // 1 hour

    /**
     * Generates a JWT token for the given user.
     * <p>
     * This method creates a JWT token with a set of claims derived from the user's details
     * (such as id, username, phone, email, and role). The token is signed using a secret key
     * and is valid for a specified amount of time.
     *
     * @param user the user for whom the token is being generated
     * @return the generated JWT token as a String
     */
    public String generateToken(User user) {
        Map<String, String> claims = new HashMap<>();
        claims.put("id", user.getId().toString());
        claims.put("username", user.getUsername());
        claims.put("phone", user.getPhone());
        claims.put("email", user.getEmail());
        claims.put("role", user.getRole().toString());
        claims.put("enable", String.valueOf(user.isEnabled()));
        return createToken(claims, new Date(System.currentTimeMillis() + TOKEN_VALIDITY));
    }

    /**
     * Creates a JWT token with the given claims and expiration time.
     *
     * @param claims a map of claims to be included in the token payload
     * @param expirationTime the expiration time of the token
     * @return the generated JWT token as a String
     */
    private String createToken(Map<String, String> claims, Date expirationTime) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject("User Details")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expirationTime)
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    /**
     * Retrieves the signing key used to sign the JWT token.
     * <p>
     * The secret key is decoded from base64 and used to generate the HMAC-SHA256 signing key.
     *
     * @return the key used to sign the JWT token
     */
    private Key getSignKey() {
        byte[] keyBytes= Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extracts the user's email, phone, or username from the JWT token.
     * <p>
     * This method decodes the JWT token and attempts to extract the user's email, phone, or username.
     * If none of these are present, it throws an exception indicating an invalid token payload.
     *
     * @param token the JWT token from which to extract user information
     * @return the email, phone, or username found in the token
     * @throws JsonProcessingException if there is an issue parsing the token payload
     */
    public String extractUser(String token) throws JsonProcessingException {
        return extractClaim(token, claim->claim.get("id").toString());

    }

    /**
     * Extracts a specific claim from the JWT token.
     * <p>
     * This method allows you to extract a specific claim from the token using the provided function.
     *
     * @param <T> the type of the claim to extract
     * @param token the JWT token from which to extract the claim
     * @param claimsResolver a function that resolves the claim from the token
     * @return the extracted claim
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extracts all claims from the JWT token.
     * <p>
     * This method parses the JWT token and returns all claims contained in the token's body.
     *
     * @param token the JWT token from which to extract claims
     * @return the claims extracted from the token
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            throw new InvalidTokenFormatException("Invalid JWT token");
        }
    }


    /**
     * Validates the JWT token against the user details.
     * <p>
     * This method checks whether the user extracted from the token matches the provided user details,
     * and ensures that the token has not expired.
     *
     * @param token the JWT token to validate
     * @param userDetails the user details to compare with the token
     * @return {@code true} if the token is valid, {@code false} otherwise
     * @throws JsonProcessingException if there is an issue extracting user information from the token
     */
    public Boolean validateToken(String token, UserDetails userDetails) throws JsonProcessingException {
        final String user = extractUser(token);
        return (user.equals(((User)userDetails).getId().toString()) && !isTokenExpired(token));
    }

    /**
     * Checks if the JWT token has expired.
     * <p>
     * This method checks the expiration claim of the token to determine if it is still valid.
     *
     * @param token the JWT token to check for expiration
     * @return {@code true} if the token has expired, {@code false} otherwise
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extracts the expiration date of the JWT token.
     * <p>
     * This method retrieves the expiration date of the token by extracting the expiration claim.
     *
     * @param token the JWT token from which to extract the expiration date
     * @return the expiration date of the token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
