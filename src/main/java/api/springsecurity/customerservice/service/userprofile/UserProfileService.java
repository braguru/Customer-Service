package api.springsecurity.customerservice.service.userprofile;

import api.springsecurity.customerservice.dto.ProfileResponse;
import api.springsecurity.customerservice.payload.ProfileRequest;

public interface UserProfileService {

    ProfileResponse getProfile();

    ProfileResponse updateProfile(ProfileRequest request);

    ProfileResponse deleteAccount();
}
