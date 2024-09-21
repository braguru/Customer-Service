package api.springsecurity.customerservice.payload;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record RegisterRequest(
        @Email(message = "Invalid email format")
       String email,

       @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
       String username,

       String password,

       @Pattern(regexp = "^\\+?[0-9]*$", message = "Phone number must be valid")
       String phone,

       @NotBlank(message = "Role is required")
       @Pattern(regexp = "^(USER|CUSTOMER)$", message = "Role must be either CUSTOMER or USER")
       String role)
{ }
