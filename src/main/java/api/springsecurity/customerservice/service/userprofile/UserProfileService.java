package api.springsecurity.customerservice.service.userprofile;

import api.springsecurity.customerservice.dto.ProfileResponse;
import api.springsecurity.customerservice.payload.ProfileRequest;

import java.io.IOException;

public interface UserProfileService {

    ProfileResponse getProfile();

    ProfileResponse updateProfile(ProfileRequest request) throws IOException;

    String deleteProfilePicture(String pictureLink);

    ProfileResponse deleteAccount();
}
