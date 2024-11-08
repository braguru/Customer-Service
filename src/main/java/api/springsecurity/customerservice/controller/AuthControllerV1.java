package api.springsecurity.customerservice.controller;

import api.springsecurity.customerservice.dto.LoginResponse;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.payload.LoginRequest;
import api.springsecurity.customerservice.payload.RegisterRequest;
import api.springsecurity.customerservice.service.authservice.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v2/auth")
public class AuthControllerV1 {

    @Qualifier("authServiceImplV1")
    private final AuthService authServicev1;

    public AuthControllerV1(@Qualifier("authServiceImplV1") AuthService authServicev1) {
        this.authServicev1 = authServicev1;
    }

    @PostMapping("/signup")
    public ResponseEntity<RegisterResponse> signup(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = authServicev1.registerUser(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        LoginResponse response = authServicev1.loginUser(loginRequest);
        return ResponseEntity.ok(response);
    }
}
