package api.springsecurity.customerservice.payload;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class ProfileRequest {
    private String username;
    private String email;
    private String profilePicture;
    private String phoneNumber;
}
