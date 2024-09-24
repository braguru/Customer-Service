package api.springsecurity.customerservice.service.authservice;

import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.entity.VerificationToken;
import api.springsecurity.customerservice.entity.enums.Role;
import api.springsecurity.customerservice.exceptions.CustomExceptions;
import api.springsecurity.customerservice.exceptions.CustomExceptions.UserAlreadyExistsException;
import api.springsecurity.customerservice.payload.RegisterRequest;
import api.springsecurity.customerservice.repositories.UserProfileRepository;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.repositories.VerificationTokenRepository;
import api.springsecurity.customerservice.service.emailservice.EmailService;
import api.springsecurity.customerservice.service.otpservice.OTPService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
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

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
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
        RegisterRequest registerRequest = new RegisterRequest(testCase.email, testCase.username, testCase.password, testCase.phone, testCase.role);

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
        RegisterRequest registerRequest = new RegisterRequest("john_doe", "john@example.com", "Password123!", null, "USER");

        // Mock password encoding
        when(passwordEncoder.encode(registerRequest.password())).thenReturn("encodedPassword");

        User user = User.builder()
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
        // Arrange
        RegisterRequest registerRequest = new RegisterRequest("john_doe", "john@example.com", "short", null, "USER");

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
        RegisterRequest registerRequest = new RegisterRequest("john_doe", "john@example.com", "Password123!", "1234567890", "USER");

        // Act
        NoEmailORPhoneNumberException exception = assertThrows(NoEmailORPhoneNumberException.class,
                ()-> authService.handleEmailBasedRegistration(registerRequest));

        // Assert
        assertEquals("Phone number should not be provided for email-based registration.", exception.getMessage());
    }

    @Test
    void testHandleEmailBasedRegistration_EmailSendingFailure() throws Exception {
        // Arrange
        RegisterRequest registerRequest = new RegisterRequest("john_doe", "john@example.com", "Password123!", null, "USER");

        // Mock password encoding
        when(passwordEncoder.encode(registerRequest.password())).thenReturn("encodedPassword");

        User user = User.builder()
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
    void handlePhoneBasedRegistration() {
    }

    @Test
    void sendVerificationEmail() {
    }

    @Test
    void confirmToken() {
    }

    @Test
    void loginUser() {
    }

    @Test
    void authenticateWithPhoneAndOtp() {
    }
}