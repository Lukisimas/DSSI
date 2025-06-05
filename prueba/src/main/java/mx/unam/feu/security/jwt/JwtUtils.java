package mx.unam.feu.security.jwt;

import jakarta.servlet.http.*;
import mx.unam.feu.security.services.UserDetailsImpl;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.*;

@Component
public class JwtUtils {	
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
	
	@Value("${mx.unam.feu.jwtSecret}")
	private String jwtSecret;
	
	@Value("${mx.unam.feu.jwtExpirationMs}")
	private int jwtExpirationMs;
	
	@Value("${mx.unam.feu.jwtCookieName}")
	private String jwtCookie;
	
	public String getJwtFromCookies(HttpServletRequest request) {	  
		Cookie cookie = WebUtils.getCookie(request, jwtCookie);
		
		if (cookie != null) 		
			return cookie.getValue();		
		else 		
			return null;	
	}
	
	public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {

    String jwt = generateTokenFromUsername(userPrincipal.getUsername());

    ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();

    return cookie;
    
	}

	public ResponseCookie getCleanJwtCookie() {
		
		ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();

    return cookie;

	}
	
	public String getUserNameFromJwtToken(String token) {
	    		
	    return Jwts.parser().verifyWith(getSigningKey())
	    		.build().parseSignedClaims(token).getPayload().getSubject();
	
	}
	
	public boolean validateJwtToken(String authToken) {		
		
		try {
			
			Jwts.parser().verifyWith(getSigningKey())
			.build().parseSignedClaims(authToken);			
			return true;
			
		} catch (SignatureException e) {
			
			logger.error("Firma JWT invalida: {}", e.getMessage());
			
		} catch (MalformedJwtException e) {
			
			logger.error("Token JWT invalido: {}", e.getMessage());
			
		} catch (ExpiredJwtException e) {
			
			logger.error("Token JWT caducó: {}", e.getMessage());
			
		} catch (UnsupportedJwtException e) {
			
			logger.error("Token JWT no está soportado: {}", e.getMessage());
			
		} catch (IllegalArgumentException e) {
			
			logger.error("La cadena JWT está vacía: {}", e.getMessage());
		}
		
		return false;
		
	}
	
	public String generateTokenFromUsername(String username) {   
		
		return Jwts.builder()
				.subject(username)
				.issuedAt(new Date())
				.expiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(getSigningKey())
				.compact();

	}
	
	private SecretKey getSigningKey() {
	    byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
	    return Keys.hmacShaKeyFor(keyBytes);
	}
			
}