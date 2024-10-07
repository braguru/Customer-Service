package api.springsecurity.customerservice.service.userprofile;

import api.springsecurity.customerservice.dto.ProfileResponse;
import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.payload.ProfileRequest;
import api.springsecurity.customerservice.repositories.UserProfileRepository;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.utils.S3Util;
import api.springsecurity.customerservice.utils.userutil.UserUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserProfileServiceImplTest {

    @InjectMocks
    UserProfileServiceImpl userProfileService;

    @Mock
    UserUtil userUtil;

    @Mock
    UserProfileRepository userProfileRepository;

    @Mock
    UserRepository userRepository;

    @Mock
    private S3Util s3Util;

    private User user;
    private UserProfile userProfile;
    private ProfileRequest profileRequest;
    private String username;
    private UUID userId;
    private MultipartFile file;


    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        username = "tester";
        userId = UUID.randomUUID();

        user = new User();
        user.setId(userId);
        user.setUsername(username);
        user.setEmail("testuser@example.com");
        user.setPhone("+1234567890");

        userProfile = new UserProfile();
        userProfile.setId(1L);
        userProfile.setUser(user);
        userProfile.setProfilePicture("profile-pic-url");

        file = mock(MultipartFile.class);
        when(file.isEmpty()).thenReturn(true);
        profileRequest = ProfileRequest.builder()
                .username("test")
                .email(user.getEmail())
                .profilePicture(file)
                .phoneNumber(user.getPhone())
                .build();
    }


    @Test
    void testGetProfile_Success() {
        when(userUtil.getCurrentUserId()).thenReturn(userId);
        when(userProfileRepository.findByUser_Id(userId)).thenReturn(Optional.of(userProfile));
       
        ProfileResponse response = userProfileService.getProfile();

        assertNotNull(response);
        assertEquals(username, response.getUsername());
        assertEquals("testuser@example.com", response.getEmail());
        assertEquals("profile-pic-url", response.getProfilePicture());
        assertEquals("+1234567890", response.getPhoneNumber());

        verify(userProfileRepository, times(1)).findByUser_Id(userId);
        verify(userUtil, times(1)).getCurrentUserId();
    }

    @Test
    void testGetProfile_ProfileNotFound() {
        when(userUtil.getCurrentUserId()).thenReturn(userId);
        when(userProfileRepository.findByUser_Id(userId)).thenReturn(Optional.empty());

        assertThrows(ProfileNotFoundException.class, () -> userProfileService.getProfile());
        verify(userProfileRepository, times(1)).findByUser_Id(userId);
        verify(userUtil, times(1)).getCurrentUserId();
    }

    @Test
    void testUpdateProfile_Success() throws IOException {
        when(userUtil.getCurrentUserId()).thenReturn(userId);
        when(userProfileRepository.findByUser_Id(userId)).thenReturn(Optional.of(userProfile));

        ProfileResponse response = userProfileService.updateProfile(profileRequest);

        verify(userProfileRepository, times(1)).save(userProfile);
        assertEquals("Profile updated successfully", response.getMessage());
        assertEquals("test", userProfile.getUser().getUsername());  // Ensure username updated
        assertEquals("testuser@example.com", userProfile.getUser().getEmail());  // Ensure email remains unchanged
        assertEquals("profile-pic-url", userProfile.getProfilePicture());  // Profile picture remains unchanged
        verify(userUtil, times(1)).getCurrentUserId();
    }

    @Test
    void testUpdateProfile_WithProfilePicture() throws IOException {
        when(userUtil.getCurrentUserId()).thenReturn(userId);
        when(userProfileRepository.findByUser_Id(userId)).thenReturn(Optional.of(userProfile));

        when(file.isEmpty()).thenReturn(false);  // New profile picture provided
        when(s3Util.uploadFile(file)).thenReturn("new-profile-pic-url");  // Mock S3 upload

        ProfileResponse response = userProfileService.updateProfile(profileRequest);

        verify(userProfileRepository, times(1)).save(userProfile);
        assertEquals("Profile updated successfully", response.getMessage());
        assertEquals("new-profile-pic-url", userProfile.getProfilePicture());  // Ensure profile picture updated
    }


    @Test
    void testUpdateProfile_ProfileNotFound() {
        when(userUtil.getCurrentUserId()).thenReturn(userId);
        when(userProfileRepository.findByUser_Id(userId)).thenReturn(Optional.empty());

        assertThrows(ProfileNotFoundException.class, () -> userProfileService.updateProfile(profileRequest));
        verify(userProfileRepository, times(1)).findByUser_Id(userId);
        verify(userUtil, times(1)).getCurrentUserId();
    }

    @Test
    void testUpdateProfile_NoValidFields() {
        ProfileRequest emptyRequest = ProfileRequest.builder().build();
        when(userUtil.getCurrentUserId()).thenReturn(userId);
        when(userProfileRepository.findByUser_Id(userId)).thenReturn(Optional.of(userProfile));

        assertThrows(ProfileDataException.class, () -> userProfileService.updateProfile(emptyRequest));
        verify(userProfileRepository, times(1)).findByUser_Id(userId);
        verify(userUtil, times(1)).getCurrentUserId();
    }

    @Test
    void testDeleteAccount_Success() {
        when(userUtil.getCurrentUserId()).thenReturn(userId);
        when(userProfileRepository.findByUser_Id(userId)).thenReturn(Optional.of(userProfile));

        ProfileResponse response = userProfileService.deleteAccount();

        verify(userRepository, times(1)).save(user);
        assertEquals("User account deleted successfully.", response.getMessage());
        assertTrue(user.isLocked());
        verify(userProfileRepository, times(1)).findByUser_Id(userId);
        verify(userUtil, times(1)).getCurrentUserId();
    }

    @Test
    void testDeleteAccount_UserNotFound() {
        when(userUtil.getCurrentUserId()).thenReturn(userId);
        when(userProfileRepository.findByUser_Id(userId)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userProfileService.deleteAccount());
        verify(userProfileRepository, times(1)).findByUser_Id(userId);
        verify(userUtil, times(1)).getCurrentUserId();
    }

}