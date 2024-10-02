package api.springsecurity.customerservice.service.authservice;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.entity.VerificationToken;
import api.springsecurity.customerservice.entity.enums.Role;
import api.springsecurity.customerservice.exceptions.CustomExceptions.UserAlreadyExistsException;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;
import api.springsecurity.customerservice.repositories.UserProfileRepository;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.repositories.VerificationTokenRepository;
import api.springsecurity.customerservice.service.emailservice.EmailService;
import api.springsecurity.customerservice.service.otpservice.OTPService;
import api.springsecurity.customerservice.utils.jwtutil.JwtUtil;
import api.springsecurity.customerservice.utils.userutil.OTPAuthenticationToken;
import jakarta.mail.MessagingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.*;

import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthServiceImplTest {

    @InjectMocks
    AuthServiceImpl authService;

    @Mock
    UserRepository userRepository;

    @Mock
    private UserProfileRepository userProfileRepository;

    @Mock
    private OTPService otpService;

    @Mock
    PasswordEncoder passwordEncoder;

    @Mock
    private EmailService emailService;

    @Mock
    private VerificationTokenRepository verificationTokenRepository;

    @Mock
    AuthenticationManager authenticationManager;

    @Mock
    JwtUtil jwtUtil;

    private User user;
    private VerificationToken token;
    private LoginRequest loginRequest;

    private OTPRequest otpRequest;
    private RegisterRequest registerRequest;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        user = new User();
        user.setEnabled(false);
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setUsername("testuser");
        user.setPhone("1234567890");

        token = new VerificationToken();
        token.setConfirmationToken("sample-token");
        token.setUser(user);
        token.setExpiryDate(LocalDateTime.now().plusMinutes(10)); // valid token


        otpRequest = new OTPRequest("1234567890", "123456");
        registerRequest = RegisterRequest.builder()
                .phone("1234567890")
                .username("testUser")
                .role("USER")
                .build();
    }

    private static class RegisterTestCase {
        String email;
        String username;
        String password; // Added password field
        String phone;
        String role;
        Optional<User> existingUser;
        Class<? extends Exception> exceptionClass;

        RegisterTestCase(String email, String username, String password, String phone, String role, Optional<User> existingUser, Class<? extends Exception> exceptionClass) {
            this.email = email;
            this.username = username;
            this.password = password; // Initialize password
            this.phone = phone;
            this.role = role;
            this.existingUser = existingUser;
            this.exceptionClass = exceptionClass;
        }
    }

    static Stream<RegisterTestCase> registerUserTestCases() {
        return Stream.of(
                // Test case where the user already exists (checks by username)
                new RegisterTestCase("john@example.com", "john_doe", "password", "1234567890", "USER",
                        Optional.of(new User(UUID.randomUUID(), "john_doe", "password", "john@example.com", "1234567890", LocalDate.of(2024, 1, 1), Role.USER, false, false)),
                        UserAlreadyExistsException.class), // User already exists

                // Test case where email already exists
                new RegisterTestCase("john@example.com", "john_doe", "password", null, "USER",
                        Optional.empty(),
                        EmailAlreadyExistException.class), // Email already exists

                // Test case where phone number already exists
                new RegisterTestCase(null, "john_doe", "password", "1234567890", "USER",
                        Optional.empty(),
                        PhoneNumberAlreadyExistsException.class), // Phone already exists

                // Test case with no email or phone number provided
                new RegisterTestCase(null, "john_doe", "password", null, "USER",
                        Optional.empty(),
                        NoEmailORPhoneNumberException.class), // No email or phone

                // Test case for invalid/empty password
                new RegisterTestCase("john@example.com", "john_doe", "password", "1234567890", "USER",
                        Optional.empty(),
                        PasswordValidationException.class) // Empty password
        );
    }


    @ParameterizedTest
    @MethodSource("registerUserTestCases")
    void testRegisterUser(RegisterTestCase testCase) {
        registerRequest = new RegisterRequest(testCase.email, testCase.username, testCase.password, testCase.phone, testCase.role);

        // Arrange - Mock repository calls based on test case expectations

        // 1. Mock username existence
        if (testCase.username != null && !testCase.username.isEmpty()) {
            when(userRepository.findByUsername(registerRequest.username()))
                    .thenReturn(testCase.existingUser);  // Mock existing user if provided
        } else {
            when(userRepository.findByUsername(registerRequest.username())).thenReturn(Optional.empty());  // Mock no user found
        }

        // 2. Mock email existence if email is provided in the request
        if (testCase.email != null && !testCase.email.isEmpty()) {
            if (testCase.exceptionClass == EmailAlreadyExistException.class) {
                when(userRepository.findByEmail(registerRequest.email()))
                        .thenReturn(Optional.of(new User(UUID.randomUUID(), "john_doe", "password", "john@example.com", "1234567890", LocalDate.of(2024, 1, 1), Role.USER, false, false)));
            } else {
                when(userRepository.findByEmail(registerRequest.email())).thenReturn(Optional.empty());  // Email not found
            }
        }

        // 3. Mock phone number existence if phone is provided in the request
        if (testCase.phone != null && !testCase.phone.isEmpty()) {
            if (testCase.exceptionClass == PhoneNumberAlreadyExistsException.class) {
                when(userRepository.findByPhone(registerRequest.phone()))
                        .thenReturn(Optional.of(new User(UUID.randomUUID(), "john_doe", "password", "john@example.com", "1234567890", LocalDate.of(2024, 1, 1), Role.USER, false, false)));
            } else {
                when(userRepository.findByPhone(registerRequest.phone())).thenReturn(Optional.empty());  // Phone number not found
            }
        }

        // Mock OTP service for all test cases (assuming OTP is sent for successful registration)
        when(otpService.sendOtp(any())).thenReturn("OTP sent successfully.");

        // Act & Assert - Check if the correct exception is thrown or registration succeeds
        if (testCase.exceptionClass != null) {
            // Assert that the expected exception is thrown
            assertThrows(testCase.exceptionClass, () -> authService.registerUser(registerRequest));
        } else {
            // Otherwise, assert that the registration succeeds and user is saved
            RegisterResponse response = authService.registerUser(registerRequest);
            assertNotNull(response);
            assertEquals(testCase.username, response.getUsername());
            verify(userRepository, times(1)).save(any(User.class));  // Verify save was called exactly once
        }
    }


    @Test
    void testHandleEmailBasedRegistration_Success() throws Exception {
        // Arrange

        registerRequest = new RegisterRequest("john_doe", "john@example.com", "Password123!", null, "USER");

        // Mock password encoding
        when(passwordEncoder.encode(registerRequest.password())).thenReturn("encodedPassword");

        user = User.builder()
                .username(registerRequest.username())
                .email(registerRequest.email())
                .date(LocalDate.now())
                .role(Role.valueOf(registerRequest.role()))
                .phone(null) // No phone number
                .enabled(false)
                .password("encodedPassword")
                .build();

        when(userRepository.save(any(User.class))).thenReturn(user);

        // Mock email sending
        doNothing().when(emailService).sendVerificationEmail(any(String.class), any(String.class));

        // Act
        RegisterResponse response = authService.handleEmailBasedRegistration(registerRequest);

        // Assert
        assertNotNull(response);
        assertEquals(user.getUsername(), response.getUsername());
        assertEquals("Registration successful. A verification email has been sent.", response.getMessage());
        verify(userRepository, times(1)).save(any(User.class));
        verify(userProfileRepository, times(1)).save(any(UserProfile.class));
        verify(emailService, times(1)).sendVerificationEmail(eq(user.getEmail()), any(String.class));
    }

    @Test
    void testHandleEmailBasedRegistration_PasswordValidationFailure() {

        registerRequest = new RegisterRequest("john_doe", "john@example.com", "short", null, "USER");
        // Act & Assert
        PasswordValidationException exception = assertThrows(
                PasswordValidationException.class,
                () -> authService.handleEmailBasedRegistration(registerRequest)
        );

        // Assert
        assertEquals("Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.", exception.getMessage());
    }

    @Test
    void testHandleEmailBasedRegistration_PhoneProvided() {
        // Arrange
        registerRequest = new RegisterRequest("john_doe", "john@example.com", "Password123!", "1234567890", "USER");

        // Act
        NoEmailORPhoneNumberException exception = assertThrows(NoEmailORPhoneNumberException.class,
                ()-> authService.handleEmailBasedRegistration(registerRequest));

        // Assert
        assertEquals("Phone number should not be provided for email-based registration.", exception.getMessage());
    }

    @Test
    void testHandleEmailBasedRegistration_EmailSendingFailure() throws Exception {
        // Arrange
        registerRequest = new RegisterRequest("john_doe", "john@example.com", "Password123!", null, "USER");

        // Mock password encoding
        when(passwordEncoder.encode(registerRequest.password())).thenReturn("encodedPassword");

        user = User.builder()
                .username(registerRequest.username())
                .email(registerRequest.email())
                .date(LocalDate.now())
                .role(Role.valueOf(registerRequest.role()))
                .phone(null)
                .enabled(false)
                .password("encodedPassword")
                .build();

        when(userRepository.save(any(User.class))).thenReturn(user);

        // Mock email sending failure
        doThrow(new EmailNotSentException("Failed to send email")).when(emailService).sendVerificationEmail(any(String.class), any(String.class));

        // Act
        RegisterResponse response = authService.handleEmailBasedRegistration(registerRequest);

        // Assert
        assertNotNull(response);
        assertEquals(user.getUsername(), response.getUsername());
        assertEquals("Registration successful but email not sent. Please try resending email later.", response.getMessage());
        // Verify that the user was saved
        verify(userRepository, times(1)).save(any(User.class));
        // Verify that the user profile was saved
        verify(userProfileRepository, times(1)).save(any(UserProfile.class));
    }

    @Test
    void testHandlePhoneBasedRegistrationSuccessful() {
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(userProfileRepository.save(any(UserProfile.class))).thenAnswer(i -> i.getArgument(0));
        when(otpService.sendOtp(any(User.class))).thenReturn("OTP sent successfully");

        RegisterResponse response = authService.handlePhoneBasedRegistration(registerRequest);

        assertNotNull(response);
        assertEquals("testUser", response.getUsername());
        assertEquals("1234567890", response.getPhone());
        assertEquals("OTP sent successfully", response.getMessage());

        verify(userRepository, times(1)).save(any(User.class));
        verify(userProfileRepository, times(1)).save(any(UserProfile.class));
        verify(otpService, times(1)).sendOtp(any(User.class));
    }

    @Test
    void testHandlePhoneBasedRegistrationPasswordProvided() {
        registerRequest = RegisterRequest.builder()
                .phone("1234567890")
                .username("testUser")
                .password("Password123!")
                .role("USER")
                .build();
        NoEmailORPhoneNumberException exception = assertThrows(NoEmailORPhoneNumberException.class,
                () -> authService.handlePhoneBasedRegistration(registerRequest));

        assertEquals("Password should not be provided for phone number-based registration.", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));

    @Test
    void testSendVerificationEmail_Success() throws Exception {
        RegisterResponse response = authService.sendVerificationEmail(user);

        verify(verificationTokenRepository, times(1)).save(any(VerificationToken.class));

        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService, times(1)).sendVerificationEmail(eq(user.getEmail()), tokenCaptor.capture());
        String capturedToken = tokenCaptor.getValue();

        assertNotNull(response);
        assertEquals(user.getId().toString(), response.getId());
        assertEquals(user.getUsername(), response.getUsername());
        assertEquals(user.getEmail(), response.getEmail());
        assertEquals("Registration successful. A verification email has been sent.", response.getMessage());
        assertNotNull(capturedToken);
    }

    @Test
    void testSendVerificationEmail_EmailNotSentException() throws Exception {
        doThrow(new EmailNotSentException("Email failed to send")).when(emailService).sendVerificationEmail(anyString(), anyString());

        EmailNotSentException exception = assertThrows(EmailNotSentException.class, () -> authService.sendVerificationEmail(user));

        verify(verificationTokenRepository, times(1)).save(any(VerificationToken.class));

        verify(emailService, times(1)).sendVerificationEmail(eq(user.getEmail()), anyString());

        assertEquals("Failed to send verification email. Please try again.", exception.getMessage());
    }

    @Test
    void testSendVerificationEmail_MessagingException() throws Exception {
        doThrow(new MessagingException("Messaging exception")).when(emailService).sendVerificationEmail(anyString(), anyString());

        assertThrows(EmailNotSentException.class, () -> authService.sendVerificationEmail(user));

        verify(verificationTokenRepository, times(1)).save(any(VerificationToken.class));

        verify(emailService, times(1)).sendVerificationEmail(eq(user.getEmail()), anyString());
    }

    @Test
    void testVerificationTokenSavedWithCorrectValues() throws Exception {
        // Call the method
        authService.sendVerificationEmail(user);

        // Capture the saved VerificationToken
        ArgumentCaptor<VerificationToken> tokenCaptor = ArgumentCaptor.forClass(VerificationToken.class);
        verify(verificationTokenRepository, times(1)).save(tokenCaptor.capture());
        VerificationToken savedToken = tokenCaptor.getValue();

        // Assert that the token contains the correct user and token
        assertNotNull(savedToken);
        assertEquals(user, savedToken.getUser());
        assertNotNull(savedToken.getConfirmationToken());  // This ensures a token is generated
        assertNotNull(savedToken.getCreatedDate());
        assertNotNull(savedToken.getExpiryDate());
        assertTrue(savedToken.getExpiryDate().isAfter(LocalDateTime.now()));
    }

    @Test
    void testConfirmTokenSuccess() {
        // Mock the repository to return the token
        when(verificationTokenRepository.findByConfirmationToken("sample-token"))
                .thenReturn(Optional.of(token));

        String result = authService.confirmToken("sample-token");

        // Verify the token is confirmed
        assertNotNull(token.getConfirmedAt());
        assertTrue(user.isEnabled());
        assertEquals("Account activated successfully", result);

        verify(userRepository, times(1)).save(user);
        verify(verificationTokenRepository, times(1)).findByConfirmationToken("sample-token");
    }

    @Test
    void testTokenNotFound() {
        // Mock the repository to return empty
        when(verificationTokenRepository.findByConfirmationToken("invalid-token"))
                .thenReturn(Optional.empty());

        assertThrows(TokenNotFoundException.class, () -> {
            authService.confirmToken("invalid-token");
        });

        verify(userRepository, never()).save(any());
        verify(verificationTokenRepository, times(1)).findByConfirmationToken("invalid-token");
    }

    @Test
    void testEmailAlreadyConfirmed() {
        // Set the token as already confirmed
        token.setConfirmedAt(LocalDateTime.now());

        // Mock the repository to return the token
        when(verificationTokenRepository.findByConfirmationToken("sample-token"))
                .thenReturn(Optional.of(token));

        assertThrows(EmailAlreadyConfirmedException.class, () -> {
            authService.confirmToken("sample-token");
        });

        verify(userRepository, never()).save(any());
        verify(verificationTokenRepository, times(1)).findByConfirmationToken("sample-token");
    }

    @Test
    void testTokenExpired() {
        // Set the token expiry to a past date
        token.setExpiryDate(LocalDateTime.now().minusMinutes(1));

        // Mock the repository to return the token
        when(verificationTokenRepository.findByConfirmationToken("sample-token"))
                .thenReturn(Optional.of(token));

        assertThrows(TokenExpiredException.class, () -> {
            authService.confirmToken("sample-token");
        });

        verify(userRepository, never()).save(any());
        verify(verificationTokenRepository, times(1)).findByConfirmationToken("sample-token");
    }

    @Test
    void testLoginUser_WithEmptyEmailAndPhone_ThrowsNoEmailORPhoneNumberException() {
        // Set up login request with empty email and phone
        loginRequest = new LoginRequest("", "", "password");

        // Assert that NoEmailORPhoneNumberException is thrown
        assertThrows(NoEmailORPhoneNumberException.class, () -> {
            authService.loginUser(loginRequest);
        });

    }

    @Test
    void testLoginUser_WithEmailAndPassword_CallsAuthenticateWithEmailAndPassword() {
        loginRequest = new LoginRequest("user@example.com", "", "password");
        // Mock the Authentication object
        Authentication authenticationMock = mock(Authentication.class);

        // Mock the authenticationManager's authenticate method to return the authentication mock
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(authenticationMock);

        // Mock the getPrincipal method to return the user
        when(authenticationMock.getPrincipal()).thenReturn(user);

        // Mock jwtService to return a dummy JWT token
        String expectedToken = "mock-jwt-token";
        when(jwtUtil.generateToken(user)).thenReturn(expectedToken);

        // Mock the method that authenticates with email and password
        LoginResponse expectedResponse = LoginResponse.builder().token(expectedToken).message("Login successful").build();

        // Call loginUser and check result
        LoginResponse result = authService.authenticateWithEmailAndPassword(loginRequest);

        // Assert that the result is as expected
        assertEquals(expectedResponse.getToken(), result.getToken());
        assertEquals(expectedResponse.getMessage(), result.getMessage());

        // Verify that jwtService.generateToken() was called
        verify(jwtUtil, times(1)).generateToken(user);

        // Verify that authenticationManager.authenticate() was called
        verify(authenticationManager, times(1)).authenticate(any(Authentication.class));
    }

    @Test
    void testAuthenticateWithPhoneAndOtpSuccess() {
        Authentication authentication = Mockito.mock(Authentication.class);

        when(authenticationManager.authenticate(any(OTPAuthenticationToken.class))).thenReturn(authentication);
        when(authentication.getDetails()).thenReturn(user);
        when(jwtUtil.generateToken(user)).thenReturn("dummyToken");

        LoginResponse response = authService.authenticateWithPhoneAndOtp(otpRequest);

        assertNotNull(response);
        assertEquals("dummyToken", response.getToken());
        assertEquals("Login successful", response.getMessage());

        verify(authenticationManager, times(1)).authenticate(any(OTPAuthenticationToken.class));
        verify(jwtUtil, times(1)).generateToken(user);
    }

    @Test
    void testAuthenticateWithPhoneAndOtpInvalidOtp() {
        when(authenticationManager.authenticate(any(OTPAuthenticationToken.class)))
                .thenThrow(new AuthenticationException("OTP validation failed") {});

        InvalidOTPException exception = assertThrows(InvalidOTPException.class,
                () -> authService.authenticateWithPhoneAndOtp(otpRequest));

        assertEquals("Invalid OTP. Please try again.", exception.getMessage());

        verify(authenticationManager, times(1)).authenticate(any(OTPAuthenticationToken.class));
        verify(jwtUtil, times(0)).generateToken(any(User.class));
    }

    @Test
    void testResendOTPSuccess() {
        when(userRepository.findByPhone("1234567890")).thenReturn(Optional.of(user));
        when(otpService.sendOtp(any())).thenReturn("OTP sent successfully.");

        String result = authService.resendOTP(otpRequest);
        assertEquals("OTP sent successfully. Please check your phone for the OTP.", result);
        verify(userRepository, times(1)).findByPhone("1234567890");
        verify(otpService, times(1)).sendOtp(any(User.class));
    }

    @Test
    void testResendOTPUserNotFound() {
        when(userRepository.findByPhone(anyString())).thenReturn(Optional.empty());

        UserNotFoundException exception = assertThrows(UserNotFoundException.class,
                () -> authService.resendOTP(otpRequest));
        assertEquals("User not found with phone number: 1234567890", exception.getMessage());
        verify(userRepository, times(1)).findByPhone("1234567890");
    }

    @Test
    void testResendOTPFailsOtpNotSent() {
        when(userRepository.findByPhone(anyString())).thenReturn(Optional.of(user));
        when(otpService.sendOtp(any(User.class))).thenThrow(new OtpNotSentException("Error sending OTP"));

        OtpNotSentException exception = assertThrows(OtpNotSentException.class,
                () -> authService.resendOTP(otpRequest));
        assertEquals("Failed to send OTP. Please try again later.", exception.getMessage());
        verify(userRepository, times(1)).findByPhone("1234567890");
        verify(otpService, times(1)).sendOtp(any(User.class));
    }

    @Test
    void testResendEmailSuccess() throws MessagingException {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString());

        authService.resendEmail(user.getEmail());

        verify(userRepository, times(1)).findByEmail(anyString());
        verify(verificationTokenRepository, times(1)).save(any(VerificationToken.class));
        verify(emailService, times(1)).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    void testResendEmailUserNotFound() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        UserNotFoundException exception = assertThrows(UserNotFoundException.class,
                () -> authService.resendEmail(user.getEmail()));
        assertEquals("User not found with email: user@example.com", exception.getMessage());
    }

    @Test
    void testResendEmailFailsEmailNotSent() throws MessagingException {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        doThrow(new MessagingException("Error sending email")).when(emailService)
                .sendVerificationEmail(anyString(), anyString());

        EmailNotSentException exception = assertThrows(EmailNotSentException.class,
                () -> authService.resendEmail(user.getEmail()));
        assertEquals("Failed to send verification email. Please try again.", exception.getMessage());
    }
}