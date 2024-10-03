package api.springsecurity.customerservice.service.userprofile;

import api.springsecurity.customerservice.dto.ProfileResponse;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.payload.ProfileRequest;
import api.springsecurity.customerservice.repositories.UserProfileRepository;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.utils.S3Util;
import api.springsecurity.customerservice.utils.userutil.UserUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserProfileServiceImpl implements UserProfileService {

    private final UserUtil userUtil;
    private final UserProfileRepository userProfileRepository;
    private final UserRepository userRepository;
    private final S3Util s3Util;


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
        UUID userId = userUtil.getCurrentUserId();
        Optional<UserProfile> profile = userProfileRepository.findByUser_Id(userId);
        if(profile.isPresent()) {
            log.info("User profile found for user: {}", userId);
            UserProfile userProfile = profile.get();
            return ProfileResponse.builder()
                    .id(userProfile.getId())
                    .username(userProfile.getUser().getUsername())
                    .email(userProfile.getUser().getEmail())
                    .profilePicture(userProfile.getProfilePicture())
                    .phoneNumber(userProfile.getUser().getPhone())
                    .idNumber(userProfile.getIdNumber())
                    .idType(userProfile.getIdType())
                    .bio(userProfile.getBio())
                    .dateOfBirth(userProfile.getDateOfBirth())
                    .build();
        }
        log.warn("User profile not found for user: {}", userId);
        throw new ProfileNotFoundException(String.format("Profile with username %s not found", userId));
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
    public ProfileResponse updateProfile(ProfileRequest request) throws IOException {
        UUID userId = userUtil.getCurrentUserId();
        Optional<UserProfile> profile = userProfileRepository.findByUser_Id(userId);

        UserProfile userProfile = profile.orElseThrow(() -> new ProfileNotFoundException("Profile not found for user: " + userId));
        boolean updated = updateUserProfileFields(request, userProfile);

        if (updated) {
            userProfileRepository.save(userProfile);
            return ProfileResponse.builder().message("Profile updated successfully").build();
        } else {
            throw new ProfileDataException("No valid fields provided for update.");
        }
    }


    /**
     * Updates the fields of the given {@link UserProfile} based on the values provided in the {@link ProfileRequest}.
     *
     * <p>This method checks each field in the {@link ProfileRequest} for validity and changes compared to the current values
     * in the {@link UserProfile}. If a new value is valid and different from the current value, the field in
     * {@link UserProfile} is updated.</p>
     *
     * @param request the {@link ProfileRequest} containing the new values for the profile fields
     * @param userProfile the {@link UserProfile} to be updated
     * @return true if at least one field was updated; false otherwise
     */
    private boolean updateUserProfileFields(ProfileRequest request, UserProfile userProfile) throws IOException {
        boolean updated = false;

        updated |= updateFieldIfDifferent(request.getUsername(), userProfile.getUser().getUsername(),
                userProfile.getUser()::setUsername);

        updated |= updateFieldIfDifferent(request.getEmail(), userProfile.getUser().getEmail(),
                userProfile.getUser()::setEmail);

        updated |= updateProfilePicture(request.getProfilePicture(), userProfile);

        updated |= updateFieldIfDifferent(request.getPhoneNumber(), userProfile.getUser().getPhone(),
                userProfile.getUser()::setPhone);

        updated |= updateFieldIfDifferent(request.getBio(), userProfile.getBio(), userProfile::setBio);

        updated |= updateFieldIfDifferent(request.getDateOfBirth(), userProfile.getDateOfBirth(),
                userProfile::setDateOfBirth);

        updated |= updateFieldIfDifferent(request.getIdType(), userProfile.getIdType(), userProfile::setIdType);

        updated |= updateFieldIfDifferent(request.getIdNumber(), userProfile.getIdNumber(),
                userProfile::setIdNumber);

        return updated;
    }


    /**
     * Updates a field in the user profile if the new value is valid and different from the current value.
     *
     * @param newValue      The new value to set in the user profile.
     * @param currentValue  The current value in the user profile.
     * @param updateFunction A {@link Consumer} that defines the action to update the field if the condition is met.
     * @return true if the field was updated; false otherwise.
     */
    private boolean updateFieldIfDifferent(String newValue, String currentValue, Consumer<String> updateFunction) {
        if (isValidField(newValue) && !newValue.equals(currentValue)) {
            updateFunction.accept(newValue);
            return true;
        }
        return false;
    }

    /**
     * Updates a field in the user profile for any type T if the new value is different from the current value.
     *
     * @param <T>            The type of the field to be updated.
     * @param newValue       The new value to set in the user profile.
     * @param currentValue   The current value in the user profile.
     * @param updateFunction A {@link Consumer} that defines the action to update the field if the condition is met.
     * @return true if the field was updated; false otherwise.
     */
    private <T> boolean updateFieldIfDifferent(T newValue, T currentValue, Consumer<T> updateFunction) {
        if (newValue != null && !newValue.equals(currentValue)) {
            updateFunction.accept(newValue);
            return true;
        }
        return false;
    }

    /**
     * Updates the profile picture in the user profile if the provided picture is not null or empty.
     *
     * @param profilePicture The new profile picture as a {@link MultipartFile}.
     * @param userProfile    The user profile to be updated.
     * @return true if the profile picture was updated; false otherwise.
     * @throws IOException if an error occurs while uploading the profile picture to S3.
     */
    private boolean updateProfilePicture(MultipartFile profilePicture, UserProfile userProfile) throws IOException {
        if (profilePicture != null && !profilePicture.isEmpty()) {
            String fileLink = s3Util.uploadFile(profilePicture);
            userProfile.setProfilePicture(fileLink);
            return true;
        }
        return false;
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

    /**
     * Deletes the account of the currently authenticated user.
     *
     * <p>This method retrieves the ID of the currently authenticated user and marks their account as locked.
     * If the user is not found, a {@link UserNotFoundException} is thrown. Once the user is marked as locked,
     * their account is considered deleted. A log entry is created to record the deletion, and a
     * {@link ProfileResponse} with a success message is returned.</p>
     *
     * @return a {@link ProfileResponse} containing a message confirming that the user account was deleted successfully
     * @throws UserNotFoundException if no user is found with the current user ID
     */
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
