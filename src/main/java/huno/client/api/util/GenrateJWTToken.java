package huno.client.api.util;

import java.time.Instant;
import java.util.Date;

import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

@Component
public class GenrateJWTToken {
private static JWTVerifier verifier ; 	
	
	public static void main(String[] args) {	
			
	}

	public  String generateToken(String principal) {
	    Instant now = Instant.now();
	    Date issuedAt = Date.from(now.minusSeconds(5));
	    Date expiresAt = Date.from(now.plusSeconds((10*60*60)));
	    Algorithm algorithm = Algorithm.HMAC256("@!234598%*");
	    Builder builder = JWT.create()
	                                    .withIssuer("abc.client.com")
	                                    .withSubject(principal)
	                                    .withIssuedAt(issuedAt)
	                                    .withExpiresAt(expiresAt);
	
	
	    return builder.sign(algorithm);
	}

	public String extractPrinciple(String token) {
	    DecodedJWT jwt = JWT.decode(token);
	    jwt.getExpiresAt();
	    return jwt.getSubject();
	}
	
	public boolean isValid(String token) {
	    try {
	    	Algorithm algorithm = Algorithm.HMAC256("@!234598%*");
	    	verifier = JWT.require(algorithm)
	                .withIssuer("xyz.client.com")
	                .build();
	    	verifier.verify(token);
	        return true;
	    } catch (JWTVerificationException e){
	       
	        return false;
	    }
	}
}

