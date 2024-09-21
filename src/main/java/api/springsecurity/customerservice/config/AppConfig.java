package api.springsecurity.customerservice.config;

import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@Configuration
@RequiredArgsConstructor
public class AppConfig {

    private final UserRepository userRepository;

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
                    .or(() -> userRepository.findByPhoneAndLockedIsFalse(identifier));

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
     * Provides an {@link AuthenticationManager} bean for handling authentication processes.
     * This bean is used by Spring Security to authenticate users.
     *
     * @param configuration the {@link AuthenticationConfiguration} used to obtain the {@link AuthenticationManager}
     * @return the {@link AuthenticationManager} bean
     * @throws Exception if an error occurs while obtaining the {@link AuthenticationManager}
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
