package api.springsecurity.customerservice.service.authservice;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.entity.enums.Role;
import api.springsecurity.customerservice.exceptions.CustomExceptions;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;
import api.springsecurity.customerservice.repositories.UserProfileRepository;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.repositories.VerificationTokenRepository;
import api.springsecurity.customerservice.service.emailservice.EmailService;
import api.springsecurity.customerservice.service.otpservice.OTPService;
import api.springsecurity.customerservice.utils.PasswordUtil;
import api.springsecurity.customerservice.utils.jwtutil.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImplV1 implements AuthService {

    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtService;
    private final OTPService otpService;
    private final UserProfileRepository userProfileRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public RegisterResponse registerUser(RegisterRequest registerRequest) {
        log.info("Registering user with email: {}, phone: {}, username: {}",
                registerRequest.email(), registerRequest.phone(), registerRequest.firstname());

        if(registerRequest.firstname() == null || registerRequest.firstname().isEmpty() ||
                registerRequest.phone() == null || registerRequest.phone().isEmpty() ||
                registerRequest.email() == null || registerRequest.email().isEmpty() ||
                registerRequest.lastname() == null || registerRequest.lastname().isEmpty()){
            log.error("Username and Phone number should be provided.");
            throw new NoEmailORPhoneNumberException("Username and Phone number should be provided.");
        }

        String username = registerRequest.firstname() + " " + registerRequest.lastname();

        if(userRepository.findByUsername(username).isPresent()){
            log.error("User with provided username already exists.");
            throw new UserAlreadyExistsException("User with provided username already exists.");
        }

        if(userRepository.findByEmail(registerRequest.email()).isPresent()){
            log.error("User with provided email already exists.");
            throw new UserAlreadyExistsException("User with provided email already exists.");
        }

        if(userRepository.findByPhone(registerRequest.phone()).isPresent()){
            log.error("User with provided phone already exists.");
            throw new UserAlreadyExistsException("User with provided phone already exists.");
        }

        return handleRegistration(registerRequest);
    }

    private RegisterResponse handleRegistration(RegisterRequest registerRequest) {
        try {
            User user = User.builder()
                    .firstname(registerRequest.firstname())
                    .lastname(registerRequest.lastname())
//                    .username(registerRequest.firstname() + " " + registerRequest.lastname())
                    .email(registerRequest.email())
                    .date(LocalDate.now())
                    .role(Role.valueOf(registerRequest.role()))
                    .phone(registerRequest.phone())
                    .enabled(false)
                    .build();
            userRepository.save(user);
            userProfileRepository.save(UserProfile.builder()
                    .user(user)
                    .profilePicture(null)
                    .build());

            return getRegisterResponse(user, otpService, log);
        } catch (IllegalArgumentException e) {
            throw new OtpNotSentException("Failed to send OTP. Please try again.");
        }

    }

    static RegisterResponse getRegisterResponse(User user, OTPService otpService, Logger log) {
        try {
            String response = otpService.sendOtp(user);
            log.info(response);
            return RegisterResponse.builder()
                    .id(String.valueOf(user.getId()))
                    .firstname(user.getFirstname())
                    .lastname(user.getLastname())
                    .email(user.getEmail())
                    .phone(user.getPhone())
                    .message(response)
                    .build();
        }catch (OtpNotSentException ex) {
            log.error("Failed to send OTP for user {}. Reason: {}", user.getPhone(), ex.getMessage());
            throw new OtpNotSentException("Registration successful but OTP not sent. Please try again.");
        }
    }

    @Override
    public String confirmToken(String token) {
        return "";
    }

    @Override
    public LoginResponse loginUser(LoginRequest loginRequest) {
        User user = userRepository.findByPhone(loginRequest.phone())
                .orElseThrow(() -> new UserNotFoundException("User not found. Please sign up"));

        try{
            String response = otpService.sendOtp(user);
            log.info(response);
            return LoginResponse.builder()
                    .message("OTP sent successfully. Check your phone for OTP.")
                    .build();
        } catch (OtpNotSentException ex) {
            log.error("Failed sending OTP: {}", ex.getMessage());
            throw new OtpNotSentException("Failed to send OTP. Please try again later.");
        }
    }

    @Override
    public LoginResponse authenticateWithPhoneAndOtp(OTPRequest otpRequest) {
        return null;
    }

    @Override
    public LoginResponse resendOTP(OTPRequest otpRequest) {
        return null;
    }

    @Override
    public void resendEmail(String email) {
        // TODO document why this method is empty
    }
}
