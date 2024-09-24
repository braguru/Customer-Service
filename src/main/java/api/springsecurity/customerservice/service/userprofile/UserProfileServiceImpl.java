package api.springsecurity.customerservice.service.userprofile;

import api.springsecurity.customerservice.dto.ProfileResponse;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.payload.ProfileRequest;
import api.springsecurity.customerservice.repositories.UserProfileRepository;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.utils.userutil.UserUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserProfileServiceImpl implements UserProfileService {

    private final UserUtil userUtil;
    private final UserProfileRepository userProfileRepository;
    private final UserRepository userRepository;


    /**
     * Retrieves the profile information of the current user.
     *
     * <p>This method fetches the user's profile based on the current user's username. It logs the process of retrieving the profile
     * and returns the profile details if found. If no profile is found for the current user, it throws a {@link ProfileNotFoundException}.
     *
     * @return a {@link ProfileResponse} containing the profile details of the current user
     * @throws ProfileNotFoundException if no profile is found for the current user
     */
    @Override
    public ProfileResponse getProfile() {
        String username = userUtil.getUserName();
        log.info("Getting user profile for user: {}", username);
        Optional<UserProfile> profile = userProfileRepository.findByUser_Username(username);
        if(profile.isPresent()) {
            log.info("User profile found for user: {}", username);
            UserProfile userProfile = profile.get();
            return ProfileResponse.builder()
                    .id(userProfile.getId())
                    .username(userProfile.getUser().getUsername())
                    .email(userProfile.getUser().getEmail())
                    .profilePicture(userProfile.getProfilePicture())
                    .phoneNumber(userProfile.getUser().getPhone())
                    .build();
        }
        log.warn("User profile not found for user: {}", username);
        throw new ProfileNotFoundException(String.format("Profile with username %s not found", username));
    }


    /**
     * Updates the profile information of the current user based on the provided {@link ProfileRequest}.
     *
     * @param request the {@link ProfileRequest} containing the updated profile information
     * @return a {@link ProfileResponse} indicating the result of the update operation
     * @throws ProfileNotFoundException if no profile is found for the current user
     * @throws ProfileDataException if no valid fields are provided for update
     */
    @Override
    public ProfileResponse updateProfile(ProfileRequest request) {
        String username = userUtil.getUserName();
        Optional<UserProfile> profile = userProfileRepository.findByUser_Username(username);

        UserProfile userProfile = profile.orElseThrow(() -> new ProfileNotFoundException("Profile not found for user: " + username));
        boolean updated = updateUserProfileFields(request, userProfile);

        if (updated) {
            userProfileRepository.save(userProfile);
            return ProfileResponse.builder().message("Profile updated successfully").build();
        } else {
            throw new ProfileDataException("No valid fields provided for update.");
        }
    }


    /**
     * Updates the fields of the {@link UserProfile} based on the provided {@link ProfileRequest}.
     *
     * @param request the {@link ProfileRequest} containing the new values for the profile fields
     * @param userProfile the {@link UserProfile} to be updated
     * @return true if at least one field was updated; false otherwise
     */
    private boolean updateUserProfileFields(ProfileRequest request, UserProfile userProfile) {
        boolean updated = false;

        if (isValidField(request.getUsername())) {
            userProfile.getUser().setUsername(request.getUsername());
            updated = true;
        }
        if (isValidField(request.getEmail())) {
            userProfile.getUser().setEmail(request.getEmail());
            updated = true;
        }
        if (isValidField(request.getProfilePicture())) {
            userProfile.setProfilePicture(request.getProfilePicture());
            updated = true;
        }
        if (isValidField(request.getPhoneNumber())) {
            userProfile.getUser().setPhone(request.getPhoneNumber());
            updated = true;
        }
        return updated;
    }


    /**
     * Checks if the given field is valid.
     *
     * @param field the field to be checked
     * @return true if the field is not null and not empty; false otherwise
     */
    private boolean isValidField(String field) {
        return field != null && !field.isEmpty();
    }


    @Override
    public ProfileResponse deleteAccount() {
        UUID userId = userUtil.getCurrentUserId();
        UserProfile userProfile = userProfileRepository.findByUser_Id(userId).orElseThrow(() -> new UserNotFoundException("User not found with ID: " + userId));
        userProfile.getUser().setLocked(true);
        userRepository.save(userProfile.getUser());
        log.info("User with ID {} deleted successfully.", userId);
        return ProfileResponse.builder().message("User account deleted successfully.").build();
    }
}
