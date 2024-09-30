package api.springsecurity.customerservice.controller;

import api.springsecurity.customerservice.dto.ProfileResponse;
import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.payload.ProfileRequest;
import api.springsecurity.customerservice.service.userprofile.UserProfileService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserProfileController.class)
@Import(TestSecurityConfig.class)
@ContextConfiguration(classes = UserProfileController.class)
class UserProfileControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserProfileService userProfileService;

    @Autowired
    private ObjectMapper objectMapper;

    private ProfileRequest profileRequest;
    private ProfileResponse profileResponse;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("testuser");
        user.setEmail("testuser@example.com");
        user.setPhone("+1234567890");

        UserProfile userProfile = new UserProfile();
        userProfile.setId(1L);
        userProfile.setUser(user);
        userProfile.setProfilePicture("profile-pic-url");

        profileRequest = ProfileRequest.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .profilePicture(userProfile.getProfilePicture())
                .phoneNumber(user.getPhone())
                .build();

        profileResponse = ProfileResponse.builder()
                .id(userProfile.getId())
                .username(userProfile.getUser().getUsername())
                .email(userProfile.getUser().getEmail())
                .profilePicture(userProfile.getProfilePicture())
                .phoneNumber(userProfile.getUser().getPhone())
                .build();
    }

    @Test
    void testGetProfile() throws Exception {
        when(userProfileService.getProfile()).thenReturn(profileResponse);

        mockMvc.perform(get("/api/v1/profile"))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(profileResponse)));
    }

    @Test
    void testUpdateProfile() throws Exception {
        when(userProfileService.updateProfile(any(ProfileRequest.class))).thenReturn(profileResponse);

        mockMvc.perform(put("/api/v1/profile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(profileRequest)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(profileResponse)));
    }

    @Test
    void testDeleteAccount() throws Exception {
        ProfileResponse deleteResponse = ProfileResponse.builder()
                .message("User account deleted successfully.")
                .build();
        when(userProfileService.deleteAccount()).thenReturn(deleteResponse);

        mockMvc.perform(delete("/api/v1/profile"))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(deleteResponse)));
    }
}