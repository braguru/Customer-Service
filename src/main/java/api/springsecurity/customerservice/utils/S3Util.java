package api.springsecurity.customerservice.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.InvalidPropertiesFormatException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class S3Util {

    @Value("${S3_BUCKET}")
    private String bucketName;

    @Value("${S3_REGION}")
    private String region;

    private final S3Client s3;

    private static final List<String> IMAGE_TYPES = Arrays.asList("image/jpeg", "image/png", "image/gif");
    private static final List<String> VIDEO_TYPES = Arrays.asList("video/mp4", "video/mpeg", "video/quicktime");


    /**
     * Uploads a file (image or video) to an Amazon S3 bucket based on its type.
     *
     * <p>The method determines the file type (image or video), constructs the appropriate
     * folder path in the S3 bucket, and uploads the file to S3. It returns the publicly
     * accessible URL of the uploaded file.</p>
     *
     * @param file The MultipartFile to upload. It can be either an image or a video.
     * @return The public URL of the uploaded file on S3.
     * @throws IOException If there is an issue reading the file input stream.
     * @throws InvalidPropertiesFormatException If the file type is not supported (neither image nor video).
     *
     * <p>Supported file types are determined by the {@code determineFileType} method, which should return
     * "IMAGE" for image files and "VIDEO" for video files.</p>
     *
     * <h4>Example S3 URL format:</h4>
     * <pre>{@code https://<bucket-name>.s3.<region>.amazonaws.com/<folder>/<file-name>}</pre>
     *
     * <h4>Usage:</h4>
     * <pre>{@code
     * MultipartFile file = // get the file from request
     * String fileUrl = uploadFile(file);
     * }</pre>
     */

    public String uploadFile(MultipartFile file) throws IOException {
        String fileType = determineFileType(file);
        String folder = "";
        String fileName = file.getOriginalFilename();

        // Check if it's an image or video
        if (fileType.equals("IMAGE")) {
            folder = "service_images/";
        } else if (fileType.equals("VIDEO")) {
            folder = "service_videos/";
        } else {
            throw new InvalidPropertiesFormatException("Invalid file type");
        }

        // Construct the S3 key (folder + filename)
        String s3Key = folder + fileName;

        // Upload file to S3
        try (InputStream inputStream = file.getInputStream()) {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(s3Key)
                    .build();

            s3.putObject(putObjectRequest, RequestBody.fromInputStream(inputStream, file.getSize()));
        }

        // Construct the URL manually
        return String.format("https://%s.s3.%s.amazonaws.com/%s", bucketName, region, s3Key);
    }


    public static String determineFileType(MultipartFile file) {
        String contentType = file.getContentType();

        if (IMAGE_TYPES.contains(contentType)) {
            return "IMAGE";
        } else if (VIDEO_TYPES.contains(contentType)) {
            return "VIDEO";
        } else {
            return "UNKNOWN";
        }
    }
}
