package api.springsecurity.customerservice.controller;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;
import api.springsecurity.customerservice.service.authservice.AuthService;
import api.springsecurity.customerservice.service.otpservice.OTPService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    private final OTPService otpService;

    @PostMapping("/signup")
    public ResponseEntity<CompletableFuture<RegisterResponse>> signup(@Valid @RequestBody RegisterRequest request) {
        CompletableFuture<RegisterResponse> response = authService.registerUser(request);
        return ResponseEntity.ok(response);
    }



    @GetMapping("verify-email")
    public String emailVerification(@RequestParam String token){
        return authService.confirmToken(token);
    }


    @PostMapping("/verify-otp")
    public ResponseEntity<RegisterResponse> verifyOTP(@RequestBody OTPRequest otpRequest){
        RegisterResponse response = otpService.verifyOTP(otpRequest);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/login")
    public ResponseEntity<CompletableFuture<LoginResponse>> login(@RequestBody LoginRequest loginRequest) {
        CompletableFuture<LoginResponse> response = authService.loginUser(loginRequest);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/login/phone")
    public ResponseEntity<LoginResponse> authenticateWithPhoneAndOtp(@Valid @RequestBody OTPRequest request){
        LoginResponse response = authService.authenticateWithPhoneAndOtp(request);
        return ResponseEntity.ok(response);
    }

}
