package api.springsecurity.customerservice.service.authservice;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;

public interface AuthService {

    RegisterResponse registerUser(RegisterRequest registerRequest);

    String confirmToken(String token);

    LoginResponse loginUser(LoginRequest loginRequest);

    LoginResponse authenticateWithPhoneAndOtp(OTPRequest otpRequest);

    LoginResponse resendOTP(OTPRequest otpRequest);

    void resendEmail(String email);
}
