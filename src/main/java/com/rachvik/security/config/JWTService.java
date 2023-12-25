package com.rachvik.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JWTService {

  private static final String SECRET_KEY =
      "b86467fb78e057ba9bd6c45764a44cf7cd5b0e9068ccc6162cc29f97fa008a91";

  public String extractUsername(final String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public String generateToken(final UserDetails userDetails) {
    return generateToken(Collections.emptyMap(), userDetails);
  }

  public boolean isValid(final String token, final UserDetails userDetails) {
    val username = extractUsername(token);
    return (userDetails.getUsername().equals(username)) && !isTokenExpired(token);
  }

  private boolean isTokenExpired(final String token) {
    return extractExpiration(token).before(new Date());
  }

  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public String generateToken(
      final Map<String, Object> extraClaims, final UserDetails userDetails) {
    return Jwts.builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + Duration.ofHours(1).toMillis()))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public <T> T extractClaim(final String token, final Function<Claims, T> claimResolver) {
    val claims = extractAllClaims(token);
    return claimResolver.apply(claims);
  }

  private Claims extractAllClaims(final String token) {
    return Jwts.parserBuilder()
        .setSigningKey(getSigningKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  private Key getSigningKey() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
  }
}
