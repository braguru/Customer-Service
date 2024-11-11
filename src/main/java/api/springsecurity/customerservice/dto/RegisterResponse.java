package api.springsecurity.customerservice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RegisterResponse {
    private String id;
    private String email;
    private String username;
    private String phone;
    private String role;
    private String message;
    private String token;
    private int statusCode;
}
