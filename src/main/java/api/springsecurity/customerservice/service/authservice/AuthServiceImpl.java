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
     * Registers a new user based on the provided {@link RegisterRequest} details asynchronously.
     * <p>
     * This method handles user registration by validating the provided email, phone, username, and other details. The process involves:
     * <ul>
     *   <li>Checking if a user with the provided email, phone number, or username already exists. If any conflict is found, it throws the relevant exception:
     *       <ul>
     *           <li>{@link UserAlreadyExistsException} if a user with the given email, username, or phone number is found.</li>
     *           <li>{@link EmailAlreadyExistException} if the email is already in use.</li>
     *           <li>{@link PhoneNumberAlreadyExistsException} if the phone number is already in use.</li>
     *       </ul>
     *   </li>
     *   <li>If no conflict is detected, the user is created and saved in the database.</li>
     *   <li>If the request includes an email, the method handles registration by sending a verification email synchronously.
     *       If it includes a phone number, it sends an OTP asynchronously using {@code otpService}.</li>
     *   <li>If an error occurs while sending the email or OTP, the method catches the exception and returns a partial success response.
     *       This indicates that the user was registered but the email/OTP could not be sent.</li>
     * </ul>
     * </p>
     * <p>
     * This method returns a {@link CompletableFuture<RegisterResponse>} which represents the outcome of the registration process.
     * It handles email-based registration synchronously and phone-based registration asynchronously.
     * </p>
     *
     * @param registerRequest the request object containing the user's registration details, such as email, phone, username, password, and role.
     * @return a {@link CompletableFuture<RegisterResponse>} representing the outcome of the registration process.
     *         If registration is successful, the response includes user details and a message regarding the OTP or email verification.
     * @throws UserAlreadyExistsException        if a user with the provided email, username, or phone number already exists.
     * @throws EmailAlreadyExistException        if the provided email is already in use.
     * @throws PhoneNumberAlreadyExistsException if the provided phone number is already in use.
     * @throws NoEmailORPhoneNumberException     if neither an email nor a phone number is provided in the registration request.
     */
    @Override
    public CompletableFuture<RegisterResponse> registerUser(RegisterRequest registerRequest) {
        log.info("Registering user with email: {}, phone: {}, username: {}",
                registerRequest.email(), registerRequest.phone(), registerRequest.username());

        if (userRepository.findByUsernameOrEmailOrPhone(registerRequest.username(), registerRequest.email(), registerRequest.phone()).isPresent()) {
            throw new UserAlreadyExistsException("User with provided email, username, or phone already exists.");
        }

        // Handle email-based registration
        if (registerRequest.email() != null && !registerRequest.email().isEmpty()) {
            if (userRepository.findByEmail(registerRequest.email()).isPresent()) {
                throw new EmailAlreadyExistException("Email already exists");
            }
            return CompletableFuture.completedFuture(handleEmailBasedRegistration(registerRequest));
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
     * Handles the user registration process using a phone number and sends an OTP asynchronously.
     * <p>
     * This method registers a user by phone number and performs the following actions:
     * <ul>
     *   <li>Validates that no password is provided (since this is a phone-based registration).</li>
     *   <li>Ensures no email is included in the request.</li>
     *   <li>Creates and saves the user in the database with the provided phone number.</li>
     *   <li>Sends an OTP to the user's phone number asynchronously using the {@code otpService}.</li>
     * </ul>
     * </p>
     * <p>
     * Upon successful OTP sending, a {@link RegisterResponse} is returned asynchronously,
     * containing details of the user and a message indicating that the OTP was sent successfully.
     * If there is an error sending the OTP, the method throws an {@link OtpNotSentException}.
     * </p>
     *
     * @param registerRequest the {@link RegisterRequest} containing the user's registration details
     *                        including username, phone number, and role (but no email or password).
     * @return a {@link CompletableFuture<RegisterResponse>} indicating the result of the registration process.
     *         On success: contains the user details and a message that the OTP was sent successfully.
     * @throws NoEmailORPhoneNumberException if a password is provided for phone-based registration.
     * @throws OtpNotSentException if the OTP could not be sent after successful registration.
     */
    public CompletableFuture<RegisterResponse> handlePhoneBasedRegistration(RegisterRequest registerRequest) {
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

        return otpService.sendOtp(user)
                .thenApply(response -> RegisterResponse.builder()
                        .id(String.valueOf(user.getId()))
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .phone(user.getPhone())
                        .message(response)
                        .build())
                .exceptionally(ex -> {
                    log.error("Failed to send OTP for user {}. Reason: {}", user.getPhone(), ex.getMessage());
                    throw new OtpNotSentException("Registration successful but OTP not sent. Please try again.");
                });
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
     * Handles user login via email/password or phone/OTP and returns a result asynchronously.
     * <p>
     * This method processes login requests by validating the provided credentials. It supports two login flows:
     * <ul>
     *   <li><strong>Email and password:</strong> If both email and password are provided, the method performs authentication using the email and password.</li>
     *   <li><strong>Phone and OTP:</strong> If only a phone number is provided, an OTP is sent to the user's phone number asynchronously.</li>
     * </ul>
     * </p>
     * <p>
     * If the authentication is successful, a {@link CompletableFuture<LoginResponse>} is returned,
     * containing the status and a message indicating the result of the login attempt. If neither
     * email nor phone number is provided, or the request is invalid, an appropriate exception is thrown.
     * </p>
     *
     * @param loginRequest the {@link LoginRequest} containing the user's login details, either email/password or phone/OTP
     * @return a {@link CompletableFuture<LoginResponse>} containing the result of the login attempt:
     *         - For email/password: The result is returned synchronously.
     *         - For phone/OTP: The result is handled asynchronously.
     * @throws NoEmailORPhoneNumberException if neither email nor phone number is provided.
     * @throws AuthenticationException       if the login request is invalid or contains improper credentials.
     */
    @Override
    public CompletableFuture<LoginResponse> loginUser(LoginRequest loginRequest) {
        if (isEmpty(loginRequest.email()) && isEmpty(loginRequest.phone())) {
            throw new NoEmailORPhoneNumberException("Email or phone number must be provided.");
        }

        if (notEmpty(loginRequest.email()) && notEmpty(loginRequest.password())) {
            return CompletableFuture.completedFuture(authenticateWithEmailAndPassword(loginRequest));
        }

        if (notEmpty(loginRequest.phone())) {
            return authenticateWithPhoneAndOtp(loginRequest.phone());
        }

        log.error("Invalid login request. Please provide valid credentials.");
        throw new AuthenticationException("Invalid login request. Please provide valid credentials.");
    }


    /**
     * Checks if a given string is null or empty.
     *
     * @param value the string to check
     * @return {@code true} if the string is null or empty, {@code false} otherwise
     */
    private boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    /**
     * Checks if a given string is not null and not empty.
     *
     * @param value the string to check
     * @return {@code true} if the string is not null and not empty, {@code false} otherwise
     */
    private boolean notEmpty(String value) {
        return !isEmpty(value);
    }


    /**
     * Authenticates a user by their phone number and sends a One-Time Password (OTP) asynchronously.
     * <p>
     * This method retrieves the user associated with the given phone number from the database.
     * If the user is found, an OTP is sent to their phone number asynchronously using the {@code otpService}.
     * The method returns a {@link CompletableFuture<LoginResponse>} that represents the result of the OTP sending process.
     * </p>
     * <p>
     * Upon successful OTP transmission, the {@link LoginResponse} contains a message indicating that the OTP
     * was sent. If an error occurs (e.g., the user is not found, or the OTP cannot be sent), the method will
     * throw a corresponding exception.
     * </p>
     *
     * @param phone the user's phone number
     * @return a {@link CompletableFuture<LoginResponse>} indicating the result of the OTP sending process.
     *         On success: contains the message "OTP sent successfully. Check your phone for OTP."
     * @throws UserNotFoundException if the user is not found in the database.
     * @throws OtpNotSentException if an error occurs while sending the OTP.
     */
    private CompletableFuture<LoginResponse> authenticateWithPhoneAndOtp(String phone) {
        User user = userRepository.findByPhone(phone)
                .orElseThrow(() -> new UserNotFoundException("User not found. Please sign up"));

        // Send OTP asynchronously and handle the result
        return otpService.sendOtp(user)
                .thenApply(otpResponse -> {
                    // OTP was sent successfully, build the LoginResponse
                    log.info(otpResponse);
                    return LoginResponse.builder()
                            .message("OTP sent successfully. Check your phone for OTP.")
                            .build();
                })
                .exceptionally(ex -> {
                    // Handle the exception when OTP is not sent successfully
                    log.error("Error sending OTP: {}", ex.getMessage());
                    throw new OtpNotSentException("Failed to send OTP. Please try again later.");
                });
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
        } catch (BadCredentialsException e) {
            log.error("Invalid credentials for user with email: {}", loginRequest.email());
            throw new BadCredentialsException("Invalid credentials. Please check your email and password.");
        }
    }


}
