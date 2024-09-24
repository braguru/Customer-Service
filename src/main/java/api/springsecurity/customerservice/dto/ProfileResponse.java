package api.springsecurity.customerservice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
//@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProfileResponse {
    private Long id;
    private String username;
    private String email;
    private String profilePicture;
    private String phoneNumber;
    private String message;
}
