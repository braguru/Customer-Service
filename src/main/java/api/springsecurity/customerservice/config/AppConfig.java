package api.springsecurity.customerservice.config;

import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.utils.userutil.OTPAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class AppConfig {

    private final UserRepository userRepository;
    private final OTPAuthenticationProvider otpAuthenticationProvider;

    /**
     * Configures a custom {@link UserDetailsService} that retrieves user details for authentication
     * based on a unique identifier, which could be a username, email, or phone number.
     * This service is utilized by Spring Security to handle user authentication and authorization.
     * <p>
     * The method attempts to find a user by searching the username, email, or phone number provided
     * as input. If no match is found for any of these fields, a {@link UsernameNotFoundException}
     * is thrown, indicating that the user does not exist in the system.
     * </p>
     *
     * @return a {@link UserDetailsService} instance that loads user data based on either
     *         username, email, or phone number for authentication purposes.
     * @throws UsernameNotFoundException if no user is found with the given identifier.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return identifier -> {
            Optional<User> userOpt = userRepository.findByUsernameAndLockedIsFalse(identifier)
                    .or(() -> userRepository.findByEmailAndLockedIsFalse(identifier))
                    .or(() -> userRepository.findByPhoneAndLockedIsFalse(identifier))
                    .or(() -> userRepository.findById(UUID.fromString(identifier)));

            return userOpt.orElseThrow(() -> new UsernameNotFoundException("User not found: " + identifier));
        };
    }


    /**
     * Configures and provides a {@link DaoAuthenticationProvider} bean, which is responsible for
     * handling user authentication by fetching user details from the database and validating
     * credentials.
     * <p>
     * This authentication provider is configured with a custom {@link UserDetailsService},
     * which retrieves user information based on email, username, or phone number. It also uses
     * a password encoder to ensure secure password validation.
     * </p>
     *
     * @return a fully configured {@link AuthenticationProvider} that authenticates users
     *         based on user details and password encoding.
     * @see DaoAuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Provides a {@link PasswordEncoder} bean that uses a delegating password encoder to handle
     * multiple password encoding formats.
     * <p>
     * The delegating password encoder defaults to bcrypt but supports other encoding
     * schemes, allowing backward compatibility with passwords encoded using different
     * algorithms. This ensures that the application can handle a variety of password formats
     * while using a secure bcrypt encoding for newly stored passwords.
     * </p>
     *
     * @return a {@link PasswordEncoder} instance that securely hashes passwords and supports
     *         multiple encoding strategies.
     * @see PasswordEncoderFactories#createDelegatingPasswordEncoder()
     */
    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * Provides an {@link AuthenticationManager} bean configured with multiple {@link AuthenticationProvider}s.
     *
     * <p>This bean is used by Spring Security to handle authentication processes by delegating to the configured
     * authentication providers, including a custom OTP authentication provider.</p>
     *
     * @return the configured {@link AuthenticationManager} bean
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        List<AuthenticationProvider> providers = List.of(authenticationProvider(), otpAuthenticationProvider);
        return new ProviderManager(providers);
    }
}
