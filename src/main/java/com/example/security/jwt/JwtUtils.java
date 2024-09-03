package com.example.security.jwt;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {

	@Value("${jwtSecret}")
	private String jwtSecret;
	
	@Value("${jwtExpirationMS}")
	private int jwtExpirationMs;
	
	public String getJwtFromHeader(HttpServletRequest request) {
		String token = request.getHeader("Authorization");
		System.out.println("Authorization header value " + token);
		if(token != null && token.startsWith("Bearer ")) {
			return token.substring(7);
		}
		return null;
	}
	
	public String generateTokenFromUserName(UserDetails userDetails) {
		String username = userDetails.getUsername();
		return Jwts.builder()
				.subject(username)
				.issuedAt(new Date())
				.expiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(key())
				.compact();
	}
	
	public String getUsernameFromJwtToken(String token) {
		return Jwts.parser()
				.verifyWith((SecretKey) key())
				.build().parseSignedClaims(token)
				.getPayload()
				.getSubject();
	}
	
	private Key key() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
	}
	
	public boolean validateJwtToken(String authToken) {
		try {
			System.out.println("Validate " + authToken);
			Jwts.parser().verifyWith((SecretKey) key()).build()
			.parseSignedClaims(authToken);
			return true;
		} catch (MalformedJwtException e) {
			System.out.println("Invalid JWT token " + e.getMessage());
		} catch (ExpiredJwtException e) {
			System.out.println("Expired JWT token " + e.getMessage());
		} catch (UnsupportedJwtException e) {
			System.out.println("Unsupported JWT token " + e.getMessage());
		} catch (IllegalArgumentException e) {
			System.out.println("JWT token is empty? " + e.getMessage());
		}
		return false;
	}
}
