package api.springsecurity.customerservice.service.authservice;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;
import org.springframework.security.core.AuthenticationException;

import java.util.concurrent.CompletableFuture;

public interface AuthService {

    /**
     * Registers a new user based on the provided registration details.
     * <p>
     * This method validates the registration request, checks for existing users,
     * and creates a new user if the provided details (username, email, phone) are unique.
     * The user is saved in the repository, and a verification email or OTP is sent as needed.
     *
     * @param registerRequest the request containing the user's registration details such as username, email, phone, and password
     * @return a {@link RegisterResponse} containing the result of the registration process, including success/failure message and status code
     */
    CompletableFuture<RegisterResponse> registerUser(RegisterRequest registerRequest);

    /**
     * Confirms a user's email by validating the provided token.
     * <p>
     * This method checks if the provided token is valid and not expired, then confirms the
     * user's email and enables the user's account if the token is valid.
     *
     * @param token the token sent to the user's email for verification
     * @return a {@link String} message indicating whether the email verification was successful or if the token is invalid or expired
     */
    String confirmToken(String token);

    /**
     * Authenticates a user based on the provided login credentials.
     * <p>
     * This method verifies the user's credentials (e.g., username/email and password),
     * and if valid, generates a token or session for the user to authenticate future requests.
     *
     * @param loginRequest the request containing the user's login credentials, such as username/email and password
     * @return a {@link String} response, which may include a token or session information for the authenticated user
     */
    CompletableFuture<LoginResponse> loginUser(LoginRequest loginRequest);

    /**
     * Authenticates a user using a phone number and a one-time password (OTP).
     *
     * @param otpRequest an {@link OTPRequest} containing the phone number and OTP.
     * @return a {@link LoginResponse} indicating the authentication result.
     * @throws IllegalArgumentException if {@code otpRequest} is null or invalid.
     * @throws AuthenticationException if the OTP is incorrect or expired.
     */
    LoginResponse authenticateWithPhoneAndOtp(OTPRequest otpRequest);
}
