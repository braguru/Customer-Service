package api.springsecurity.customerservice.payload;

import api.springsecurity.customerservice.entity.enums.ID;
import lombok.Builder;
import lombok.Getter;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;

@Builder
@Getter
public class ProfileRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String phoneNumber;
    private MultipartFile profilePicture;
    private String bio;
    private LocalDate dateOfBirth;
    private ID idType;
    private String idNumber;
}
