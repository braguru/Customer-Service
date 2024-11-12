package api.springsecurity.customerservice.payload;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;

@Builder
public record RegisterRequest(
        @Email(message = "Invalid email format")
       String email,

       String firstname,

        String lastname,

       String password,

       @Pattern(regexp = "^\\+?[0-9]*$", message = "Phone number must be valid")
       String phone

)
{ }
