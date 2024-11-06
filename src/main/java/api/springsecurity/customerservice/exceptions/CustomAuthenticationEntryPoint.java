package api.springsecurity.customerservice.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.security.SignatureException;

/**
 * This class is used to handle the AuthenticationEntryPoint.
 * It is used to handle the AuthenticationException.
 * It is used to handle Authentication Failures (When a user is not authenticated).
 */
@Component("customAuthenticationEntryPoint")
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Qualifier("handlerExceptionResolver")
    private final HandlerExceptionResolver resolver;

    // Constructor without @Qualifier (optional, Lombok can generate it if no other dependencies need injecting)
    public CustomAuthenticationEntryPoint(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Object cause =  request.getAttribute("authException");

        switch(cause) {
            case ExpiredJwtException exp ->
                    resolver.resolveException(request, response, null, new ExpiredJwtException(exp.getHeader(), exp.getClaims(), exp.getMessage()));
            case MalformedJwtException malformedJwtException ->
                    resolver.resolveException(request, response, null, new MalformedJwtException(malformedJwtException.getMessage()));
            case SignatureException signatureException ->
                    resolver.resolveException(request, response, null, new SignatureException(signatureException.getMessage()));
            case BadCredentialsException badCredentialsException ->
                    resolver.resolveException(request, response, null, new BadCredentialsException(badCredentialsException.getMessage()));
            case InsufficientAuthenticationException insufficientAuthenticationException ->
                    resolver.resolveException(request, response, null, new InsufficientAuthenticationException(insufficientAuthenticationException.getMessage()));
            case CustomExceptions.InvalidTokenFormatException exp -> resolver.resolveException(request, response, null, new CustomExceptions.InvalidTokenFormatException(exp.getMessage()));
            case null, default -> resolver.resolveException(request, response, null, authException);
        }
    }

}
