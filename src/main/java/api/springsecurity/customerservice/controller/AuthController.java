package api.springsecurity.customerservice.controller;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;
import api.springsecurity.customerservice.service.authservice.AuthService;
import api.springsecurity.customerservice.service.otpservice.OTPService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
public class AuthController {


    @Qualifier("authServiceImpl")
    private final AuthService authService;
    private final OTPService otpService;

    public AuthController(@Qualifier("authServiceImpl") AuthService authService, OTPService otpService) {
        this.authService = authService;
        this.otpService = otpService;
    }

//    @PostMapping("/signup")
//    public ResponseEntity<RegisterResponse> signup(@Valid @RequestBody RegisterRequest request) {
//        RegisterResponse response = authService.registerUser(request);
//        return ResponseEntity.ok(response);
//    }

    @GetMapping("verify-email")
    public String emailVerification(@RequestParam String token){
        return authService.confirmToken(token);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<RegisterResponse> verifyOTP(@RequestBody OTPRequest otpRequest){
        RegisterResponse response = otpService.verifyOTP(otpRequest);
        return ResponseEntity.ok(response);
    }

//    @PostMapping("/login")
//    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
//        LoginResponse response = authService.loginUser(loginRequest);
//        return ResponseEntity.ok(response);
//    }

//    @PostMapping("/login/phone")
//    public ResponseEntity<LoginResponse> authenticateWithPhoneAndOtp(@Valid @RequestBody OTPRequest request){
//        LoginResponse response = authService.authenticateWithPhoneAndOtp(request);
//        return ResponseEntity.ok(response);
//    }

    @PostMapping("/resend-otp")
    public ResponseEntity<String> resendOtp(@RequestBody OTPRequest otpRequest){
        String response = authService.resendOTP(otpRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-email")
    public ResponseEntity<String> resendEmail(@RequestParam String email){
        authService.resendEmail(email);
        return ResponseEntity.ok("Email sent successfully");
    }

}
