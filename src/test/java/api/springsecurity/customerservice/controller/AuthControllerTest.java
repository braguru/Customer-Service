package api.springsecurity.customerservice.controller;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;
import api.springsecurity.customerservice.service.authservice.AuthService;
import api.springsecurity.customerservice.service.otpservice.OTPService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@ContextConfiguration(classes = {AuthController.class})
@Import(TestSecurityConfig.class)
class AuthControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private OTPService otpService;

    @Autowired
    private ObjectMapper objectMapper;

    private RegisterRequest registerRequest;
    private RegisterResponse registerResponse;
    private OTPRequest otpRequest;
    private LoginRequest loginRequest;
    private LoginResponse loginResponse;

    @BeforeEach
    void setUp() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("testuser@example.com");
        user.setUsername("testuser");

        registerRequest = RegisterRequest.builder()
                .email(user.getEmail())
                .username(user.getUsername())
                .password("password")
                .phone("+1234567890")
                .role("USER")
                .build();

        registerResponse = RegisterResponse.builder()
                .id(String.valueOf(user.getId()))
                .email(user.getEmail())
                .username(user.getUsername())
                .phone("+1234567890")
                .role("USER")
                .build();

        otpRequest = OTPRequest.builder()
                .code("123456")
                .number("+1234567890")
                .build();

        loginRequest = LoginRequest.builder()
                .phone("+1234567890")
                .email(user.getEmail())
                .password("password")
                .build();

        loginResponse = LoginResponse.builder()
                .message("Login successful")
                .token("test-jwt")
                .build();
    }

    @Test
    void signup() throws Exception {
        when(authService.registerUser(any(RegisterRequest.class))).thenReturn(registerResponse);

        mockMvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(registerResponse)));
    }


    @Test
    void testEmailVerification() throws Exception {
        when(authService.confirmToken("token")).thenReturn("Verification Successful");

        mockMvc.perform(get("/api/v1/auth/verify-email")
                        .param("token", "token"))
                .andExpect(status().isOk())
                .andExpect(content().string("Verification Successful"));
    }

    @Test
    void testVerifyOTP() throws Exception {
        when(otpService.verifyOTP(any(OTPRequest.class))).thenReturn(registerResponse);

        mockMvc.perform(post("/api/v1/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otpRequest)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(registerResponse)));
    }

    @Test
    void testLogin() throws Exception {
        when(authService.loginUser(any(LoginRequest.class))).thenReturn(loginResponse);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(loginResponse)));
    }

    @Test
    void testAuthenticateWithPhoneAndOtp() throws Exception {
        when(authService.authenticateWithPhoneAndOtp(any(OTPRequest.class))).thenReturn(loginResponse);

        mockMvc.perform(post("/api/v1/auth/login/phone")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otpRequest)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(loginResponse)));
    }
}