package api.springsecurity.customerservice.service.authservice;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;

import java.util.concurrent.CompletableFuture;

public interface AuthService {


    CompletableFuture<RegisterResponse> registerUser(RegisterRequest registerRequest);

    String confirmToken(String token);

    CompletableFuture<LoginResponse> loginUser(LoginRequest loginRequest);

    LoginResponse authenticateWithPhoneAndOtp(OTPRequest otpRequest);
}
