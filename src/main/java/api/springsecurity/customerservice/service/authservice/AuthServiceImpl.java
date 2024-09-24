package api.springsecurity.customerservice.service.authservice;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.entity.VerificationToken;
import api.springsecurity.customerservice.entity.enums.Role;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;
import api.springsecurity.customerservice.repositories.UserProfileRepository;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.repositories.VerificationTokenRepository;
import api.springsecurity.customerservice.service.emailservice.EmailService;
import api.springsecurity.customerservice.utils.jwtutil.JwtUtil;
import api.springsecurity.customerservice.service.otpservice.OTPService;
import api.springsecurity.customerservice.utils.userutil.OTPAuthenticationToken;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtService;
    private final OTPService otpService;
    private final UserProfileRepository userProfileRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Registers a new user based on the provided {@link RegisterRequest} details.
     * <p>
     * This method executes the following steps:
     * <ul>
     *   <li>Checks for an existing user with the specified email, phone number, or username.
     *       If a conflict is found, it throws an appropriate exception.</li>
     *   <li>If no conflict is detected, the new user is created and saved in the database.</li>
     *   <li>Sends a verification email or OTP based on the provided registration details.</li>
     *   <li>If an error occurs during the email or OTP sending process, the method catches the exception
     *       and returns a partial success response, indicating that registration was successful
     *       but the email/OTP could not be sent.</li>
     * </ul>
     *
     * @param registerRequest the request object containing user registration details, including email,
     *                        phone number, username, password, and role.
     * @return a {@link CompletableFuture<RegisterResponse>} representing the outcome of the registration process.
     * @throws UserAlreadyExistsException        if a user with the provided email, username, or phone number already exists.
     * @throws EmailAlreadyExistException        if the provided email already exists in the system.
     * @throws PhoneNumberAlreadyExistsException if the provided phone number already exists in the system.
     * @throws NoEmailORPhoneNumberException     if neither an email nor a phone number is provided in the request.
     */
    @Override
    public RegisterResponse registerUser(RegisterRequest registerRequest) {
        log.info("Registering user with email: {}, phone: {}, username: {}",
                registerRequest.email(), registerRequest.phone(), registerRequest.username());

        if (userRepository.findByUsername(registerRequest.username()).isPresent()) {
            throw new UserAlreadyExistsException("User with provided email, username, or phone already exists.");
        }

        // Handle email-based registration
        if (registerRequest.email() != null && !registerRequest.email().isEmpty()) {
            if (userRepository.findByEmail(registerRequest.email()).isPresent()) {
                throw new EmailAlreadyExistException("Email already exists");
            }
            return handleEmailBasedRegistration(registerRequest);
        }

        if (registerRequest.phone() != null && !registerRequest.phone().isEmpty()) {
            if (userRepository.findByPhone(registerRequest.phone()).isPresent()) {
                throw new PhoneNumberAlreadyExistsException("Phone number already exists.");
            }

            return handlePhoneBasedRegistration(registerRequest);
        }

        throw new NoEmailORPhoneNumberException("Email or phone number must be provided.");
    }


    /**
     * Handles the user registration process using an email address.
     * <p>
     * This method performs the following actions:
     * <ul>
     *   <li>Validates that a password is provided and meets the required criteria.</li>
     *   <li>Ensures no phone number is included in the request.</li>
     *   <li>Creates and saves the user in the database.</li>
     *   <li>Attempts to send a verification email to the provided address.
     *       If sending fails, a partial success response is returned.</li>
     * </ul>
     *
     * @param registerRequest the {@link RegisterRequest} containing the user's registration details.
     * @return a {@link RegisterResponse} indicating the result of the registration process:
     *         - Success: message indicating the registration was successful.
     *         - Failure: message indicating the email was not sent.
     * @throws PasswordValidationException if the password format is invalid.
     * @throws NoEmailORPhoneNumberException if a required field is missing or improperly provided.
     */
    public RegisterResponse handleEmailBasedRegistration(RegisterRequest registerRequest) {
        if (registerRequest.password() == null || registerRequest.password().isEmpty()) {
            throw new NoEmailORPhoneNumberException("Password is required for email-based registration.");
        } else {
            // Validate the password
            String password = registerRequest.password();
            String passwordPattern = "^(?=.*\\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,}$";

            if (!password.matches(passwordPattern)) {
                throw new PasswordValidationException("Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.");
            }
        }

        if (registerRequest.phone() != null && !registerRequest.phone().isEmpty()) {
            throw new NoEmailORPhoneNumberException("Phone number should not be provided for email-based registration.");
        }

        User user = User.builder()
                .username(registerRequest.username())
                .email(registerRequest.email())
                .date(LocalDate.now())
                .role(Role.valueOf(registerRequest.role()))
                .phone(null) // No phone number
                .enabled(false)
                .password(passwordEncoder.encode(registerRequest.password()))
                .build();
        userRepository.save(user);
        userProfileRepository.save(UserProfile.builder()
                .user(user)
                .profilePicture(null)
                .build());
        try {
            log.info("Sending verification email to {}", user.getEmail());
            return sendVerificationEmail(user);
        } catch (EmailNotSentException e) {
            log.error("Email sending failed: {}", e.getMessage());
            return RegisterResponse.builder()
                    .id(String.valueOf(user.getId()))
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .message("Registration successful but email not sent. Please try resending email later.")
                    .build();
        }
    }

    /**
     * Handles the user registration process using a phone number.
     * <p>
     * This method performs the following actions:
     * <ul>
     *   <li>Validates that no password is provided, as phone-based registration should not include a password.</li>
     *   <li>Creates and saves the user in the database with their phone number and other relevant details.</li>
     *   <li>Sends an OTP to the user's phone number for verification.</li>
     *   <li>If OTP sending fails, an {@link OtpNotSentException} is thrown to indicate the registration succeeded, but the OTP could not be sent.</li>
     * </ul>
     * </p>
     * <p>
     * This method returns a {@link RegisterResponse} indicating the result of the registration process, including a message if the OTP was sent successfully.
     * </p>
     *
     * @param registerRequest the {@link RegisterRequest} containing the user's registration details, such as username, phone number, and role.
     * @return a {@link RegisterResponse} indicating the result of the registration process, including user details and an OTP-related message.
     * @throws NoEmailORPhoneNumberException if a password is provided for phone-based registration.
     * @throws OtpNotSentException if the OTP could not be sent after successful registration.
     */
    public RegisterResponse handlePhoneBasedRegistration(RegisterRequest registerRequest) {
        if (registerRequest.password() != null && !registerRequest.password().isEmpty()) {
            throw new NoEmailORPhoneNumberException("Password should not be provided for phone number-based registration.");
        }

        User user = User.builder()
                .username(registerRequest.username())
                .email(null) // No email
                .date(LocalDate.now())
                .role(Role.valueOf(registerRequest.role()))
                .phone(registerRequest.phone())
                .enabled(false)
                .password(null) // No password
                .build();
        userRepository.save(user);
        userProfileRepository.save(UserProfile.builder()
                .user(user)
                .profilePicture(null)
                .build());

        try {
            String response = otpService.sendOtp(user);
            // On success, return the registration response
            return RegisterResponse.builder()
                    .id(String.valueOf(user.getId()))
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .phone(user.getPhone())
                    .message(response)
                    .build();
        }catch (OtpNotSentException ex) {
            // On failure, handle the exception and provide a fallback response
            log.error("Failed to send OTP for user {}. Reason: {}", user.getPhone(), ex.getMessage());
            throw new OtpNotSentException("Registration successful but OTP not sent. Please try again.");
        }
    }


    /**
     * Sends a verification email to the specified user by generating a unique verification token and saving it.
     * <p>
     * This method performs the following actions:
     * <ul>
     *   <li>Generates a unique verification token and associates it with the user.</li>
     *   <li>Saves the verification token in the database.</li>
     *   <li>Attempts to send the verification email to the user's email address.</li>
     *   <li>If the email is successfully sent, a success response is returned.
     *       If an error occurs during the email sending process, an appropriate exception is thrown.</li>
     * </ul>
     *
     * @param user The {@link User} to whom the verification email will be sent.
     * @return A {@link RegisterResponse} containing the result of the operation:
     *         - Success: message "Registration successful. A verification email has been sent."
     * @throws EmailNotSentException if the email fails to send or if there is a messaging error.
     */
    public RegisterResponse sendVerificationEmail(User user) throws EmailNotSentException {
        try {
            String token = UUID.randomUUID().toString();
            VerificationToken verificationToken = new VerificationToken();
            verificationToken.setUser(user);
            verificationToken.setConfirmationToken(token);
            verificationToken.setCreatedDate(LocalDateTime.now());
            verificationToken.setExpiryDate(LocalDateTime.now().plusDays(1));
            verificationTokenRepository.save(verificationToken);
            emailService.sendVerificationEmail(user.getEmail(), token);

            log.info("Verification email sent successfully to {}", user.getEmail());
            return RegisterResponse.builder()
                    .id(String.valueOf(user.getId()))
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .phone(user.getPhone())
                    .message("Registration successful. A verification email has been sent.")
                    .build();
        } catch (EmailNotSentException | MessagingException e) {
            log.error("Failed to send verification email to {}: {}", user.getEmail(), e.getMessage());
            throw new EmailNotSentException("Failed to send verification email. Please try again.");
        }
    }


    /**
     * Confirms the verification token and activates the user's account.
     * <p>
     * This method verifies the provided token, checks if it's expired or already confirmed,
     * and then activates the user's account if valid.
     *
     * @param token the token to be confirmed
     * @return a message indicating the account has been activated successfully
     *
     * @throws TokenNotFoundException if the token is not found
     * @throws EmailAlreadyConfirmedException if the token has already been confirmed
     * @throws TokenExpiredException if the token is expired
     */
    @Transactional
    public String confirmToken(String token) {
        VerificationToken tokenRepository = verificationTokenRepository.findByConfirmationToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Token not found"));

        if (tokenRepository.getConfirmedAt() != null) {
            throw new EmailAlreadyConfirmedException("Email already confirmed");
        }

        LocalDateTime expiredAt = tokenRepository.getExpiryDate();
        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Token expired");
        }

        tokenRepository.setConfirmedAt(LocalDateTime.now());
        User user = tokenRepository.getUser();
        user.setEnabled(true);
        userRepository.save(user);
        return "Account activated successfully";
    }


    /**
     * Logs in a user with email and password or phone and OTP.
     *
     * <p>This method handles login requests by validating the provided credentials. It supports two login methods:
     * via email and password, or via phone and OTP. If the phone is provided, it sends an OTP to the user's phone.
     * If authentication is successful, it returns a {@link LoginResponse} with a message indicating the result.</p>
     *
     * @param loginRequest the {@link LoginRequest} containing the user's login information (email/password or phone)
     * @return a {@link CompletableFuture<LoginResponse>} indicating the result of the login attempt, including status and messages
     * @throws NoEmailORPhoneNumberException if neither email nor phone number is provided
     * @throws AuthenticationException if the login request is invalid
     */
    @Override
    public LoginResponse loginUser(LoginRequest loginRequest) {
        if (isEmpty(loginRequest.email()) && isEmpty(loginRequest.phone())) {
            throw new NoEmailORPhoneNumberException("Email or phone number must be provided.");
        }

        if (notEmpty(loginRequest.email()) && notEmpty(loginRequest.password())) {
            return authenticateWithEmailAndPassword(loginRequest);
        }

        if (notEmpty(loginRequest.phone())) {
            return authenticateWithPhoneAndOtp(loginRequest.phone());
        }

        log.error("Invalid login request. Please provide valid credentials.");
        throw new AuthenticationException("Invalid login request. Please provide valid credentials.");
    }


    private boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    private boolean notEmpty(String value) {
        return !isEmpty(value);
    }

    /**
     * Authenticates a user using their phone number and sends an OTP.
     * <p>
     * This method retrieves the user by their phone number and sends an OTP.
     * If the user is not found, it throws a {@link UserNotFoundException}.
     * Upon successfully sending the OTP, it returns a {@link LoginResponse}.
     * </p>
     *
     * @param phone the user's phone number
     * @return a {@link LoginResponse} indicating the result of the OTP sending process:
     *         - Success: message "OTP sent successfully. Check your phone for OTP."
     * @throws UserNotFoundException if the user is not found
     * @throws RuntimeException if there is an error sending the OTP
     */
    private LoginResponse authenticateWithPhoneAndOtp(String phone) {
        User user = userRepository.findByPhone(phone)
                .orElseThrow(() -> new UserNotFoundException("User not found. Please sign up"));

        try{
            String response = otpService.sendOtp(user);
            log.info(response);
            return LoginResponse.builder()
                    .message("OTP sent successfully. Check your phone for OTP.")
                    .build();
        } catch (OtpNotSentException ex) {
            log.error("Error sending OTP: {}", ex.getMessage());
            throw new OtpNotSentException("Failed to send OTP. Please try again later.");
        }
    }




    /**
     * Authenticates a user using a phone number and OTP.
     *
     * <p>This method verifies the OTP provided for the user's phone number. If the OTP is valid,
     * it generates a JWT token for the user and returns a {@link LoginResponse} with the token and a success message.
     * If the OTP is invalid, it throws an {@link InvalidOTPException}.</p>
     *
     * @param otpRequest the {@link OTPRequest} containing the phone number and OTP
     * @return a {@link LoginResponse} indicating the result of the OTP authentication, including status and JWT token if successful
     */
//    public LoginResponse authenticateWithPhoneAndOtp(OTPRequest otpRequest) {
//        User user = userRepository.findByPhone(otpRequest.number())
//                .orElseThrow(() -> new UserNotFoundException("User not found. Please sign up"));
//
//        RegisterResponse otpResponse = otpService.verifyOTP(otpRequest);
//        // Validate OTP (this is just a placeholder, adjust logic to your actual OTP validation)
//        if (!otpService.verifyOTP(otpRequest).getMessage().equals("OK")) {
//            log.error("OTP validation failed for user with phone number: {}. Reason: {}", otpRequest.number(), otpResponse.getMessage());
//            throw new InvalidOTPException("Invalid OTP. Please try again.");
//        }
//        Authentication authenticate = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
//        String jwtToken = jwtService.generateToken(user);
//        return LoginResponse.builder()
//                .token(jwtToken)
//                .message("Login successful")
//                .build();
//    }
    public LoginResponse authenticateWithPhoneAndOtp(OTPRequest otpRequest) {
        try {
            Authentication authenticate = authenticationManager.authenticate(
                    new OTPAuthenticationToken(otpRequest.number(), otpRequest.code()));

            // Cast the authenticated principal to your custom User class
            User user = (User) authenticate.getPrincipal();

            // Generate JWT token
            String jwtToken = jwtService.generateToken(user);
            log.info("User with phone number: {} logged in successfully", otpRequest.number());
            return LoginResponse.builder()
                    .token(jwtToken)
                    .message("Login successful")
                    .build();
        } catch (AuthenticationException e) {
            log.error("OTP validation failed for user with phone number: {}. Reason: {}", otpRequest.number(), e.getMessage());
            throw new InvalidOTPException("Invalid OTP. Please try again. ");
        }
    }

    /**
     * Authenticates a user using their email and password.
     * <p>
     * This method uses the {@code authenticationManager} to authenticate the user's email and password.
     * If authentication is successful, a JWT token is generated and returned.
     * If authentication fails or the user is not found, appropriate error messages are thrown.
     * </p>
     *
     * @param loginRequest the login request containing the user's email and password.
     * @return a {@link LoginResponse} containing the JWT token and a success message.
     * @throws DisabledException if the account is disabled or locked.
     * @throws BadCredentialsException if the credentials are invalid.
     */
    private LoginResponse authenticateWithEmailAndPassword(LoginRequest loginRequest) {
        try {
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.email(), loginRequest.password()));

            // Cast the authenticated principal to your custom User class
            User user = (User) authenticate.getPrincipal();

            String jwtToken = jwtService.generateToken(user);
            log.info("User with email: {} logged in successfully", loginRequest.email());
            return LoginResponse.builder()
                    .token(jwtToken)
                    .message("Login successful")
                    .build();
        } catch (DisabledException | LockedException e) {
            log.error("User with email: {} is disabled or locked", loginRequest.email());
            throw new DisabledException("Account not activated");
//            throw new UnActivatedAccountException("Account not activated");
        } catch (BadCredentialsException e) {
            log.error("Invalid credentials for user with email: {}", loginRequest.email());
            throw new BadCredentialsException("Invalid credentials. Please check your email and password.");
        }
    }


}
