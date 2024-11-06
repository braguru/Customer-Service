package api.springsecurity.customerservice.config;

import api.springsecurity.customerservice.utils.jwtutil.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * A filter for handling JWT (JSON Web Token) authentication.
 * <p>
 * This filter is invoked once per request and performs the following actions:
 * - Extracts the JWT token from the `Authorization` header of the incoming HTTP request.
 * - Validates the token using the `JwtService`.
 * - Loads user details from the `UserDetailsService`.
 * - If the token is valid and user details are successfully loaded, it sets the authentication in the `SecurityContext`.
 * <p>
 * It extends {@link OncePerRequestFilter} to ensure that the filter is executed only once per request.
 */
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    /**
     * Processes the HTTP request to extract and validate the JWT token.
     * <p>
     * This method extracts the token from the `Authorization` header, validates it, and if the token is valid,
     * sets the authentication in the `SecurityContext` based on the extracted user details.
     *
     * @param request the HTTP request to process
     * @param response the HTTP response to process
     * @param filterChain the filter chain to pass the request and response to the next filter
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs during the request processing
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            final String authHeader = request.getHeader("Authorization");
            String token = null;
            String user = null;

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
                user = jwtUtil.extractUser(token);
            }
            // Validate token and set authentication if valid
            if (user != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(user);
                if (Boolean.TRUE.equals(jwtUtil.validateToken(token, userDetails))) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            request.setAttribute("authException", e);
            filterChain.doFilter(request, response);
        }
    }
}
