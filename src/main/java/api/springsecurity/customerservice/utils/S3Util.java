package api.springsecurity.customerservice.utils;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.InvalidPropertiesFormatException;
import java.util.List;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;

@Component
@RequiredArgsConstructor
public class S3Util {

    private static final Logger log = LoggerFactory.getLogger(S3Util.class);
    public static final String IMAGE = "IMAGE";
    public static final String VIDEO = "VIDEO";
    @Value("${S3_BUCKET}")
    private String bucketName;

    @Value("${S3_REGION}")
    private String region;

    private final S3Client s3;

    private static final String ERROR_DELETING_FILE = "Error deleting file from S3: ";

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
        if (fileType.equals(IMAGE)) {
            folder = "service_images/";
        } else if (fileType.equals(VIDEO)) {
            folder = "service_videos/";
        } else {
            throw new InvalidFileTypeException("Invalid file type");
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
        } catch (SdkException e) {
            throw new S3Exception(ERROR_DELETING_FILE + e.getMessage());
        }

        // Construct the URL manually
        return String.format("https://%s.s3.%s.amazonaws.com/%s", bucketName, region, s3Key);
    }


    /**
     * Handles the deletion of a file from an S3 bucket using its URL.
     * <p>
     * This method extracts the S3 key from the file URL, streams the file to process
     * it momentarily, and then deletes it from the S3 bucket.
     *
     * @param fileUrl The full URL of the file stored in the S3.
     * @return A success message indicating the file was deleted.
     * @throws S3Exception if an error occurs during streaming or deletion.
     */
    public String handleFileDeletion(String fileUrl) {
        String s3Key = extractS3KeyFromUrl(fileUrl, bucketName, region);
        try (InputStream inputStream = streamFileFromS3(s3Key)) {
            return deleteFileFromS3(s3Key);
        } catch (IOException e) {
            throw new S3Exception("Error streaming file from S3: " + e.getMessage());
        } catch (SdkException e) {
            throw new S3Exception(ERROR_DELETING_FILE + e.getMessage());
        }
    }

    /**
     * Extracts the S3 key from the given file URL.
     * <p>
     * Removes the base URL consisting of the bucket name and region to isolate the key
     * that uniquely identifies the file within the bucket.
     *
     * @param fileUrl   The full URL of the file in the S3 bucket.
     * @param bucketName The name of the S3 bucket.
     * @param region    The AWS region where the bucket is located.
     * @return The extracted S3 key that identifies the file.
     */
    public String extractS3KeyFromUrl(String fileUrl, String bucketName, String region) {
        String baseUrl = String.format("https://%s.s3.%s.amazonaws.com/", bucketName, region);
        return fileUrl.replace(baseUrl, "");
    }

    /**
     * Streams a file from the S3 bucket based on the specified S3 key.
     * <p>
     * This method fetches the object from S3, providing an InputStream to its contents.
     * The caller must close this InputStream to avoid resource leaks.
     *
     * @param s3Key The S3 key that identifies the file in the bucket.
     * @return An InputStream to read the file's contents.
     * @throws SdkException If an error occurs while accessing the file on S3.
     */
    public InputStream streamFileFromS3(String s3Key) {
        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket(bucketName)
                .key(s3Key)
                .build();
        return s3.getObject(getObjectRequest);
    }

    /**
     * Deletes the specified file from the S3 bucket using the S3 key.
     * <p>
     * This method interacts with the AWS SDK to delete an object from a bucket.
     * The object is identified by its unique key within the bucket.
     *
     * @param s3Key The S3 key that identifies the file in the bucket.
     * @return A success message indicating the file was deleted.
     * @throws S3Exception If an error occurs during deletion.
     */
    public String deleteFileFromS3(String s3Key) {
        try {
            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(bucketName)
                    .key(s3Key)
                    .build();
            s3.deleteObject(deleteObjectRequest);
            log.info("File deleted successfully: {} " , s3Key);
            return String.format("File %s deleted successfully.", s3Key);
        } catch (SdkException e) {
            throw new S3Exception(ERROR_DELETING_FILE + e.getMessage());
        }
    }


    public static String determineFileType(MultipartFile file) {
        String contentType = file.getContentType();

        if (IMAGE_TYPES.contains(contentType)) {
            return IMAGE;
        } else if (VIDEO_TYPES.contains(contentType)) {
            return VIDEO;
        } else {
            return "UNKNOWN";
        }
    }
}
