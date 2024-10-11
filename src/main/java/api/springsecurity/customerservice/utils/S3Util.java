package api.springsecurity.customerservice.utils;

import api.springsecurity.customerservice.dto.S3ObjectResponse;
import api.springsecurity.customerservice.exceptions.CustomExceptions;
import lombok.RequiredArgsConstructor;
import org.imgscalr.Scalr;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

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
    private final S3AsyncClient s3AsyncClient;

    private static final String ERROR_DELETING_FILE = "Error deleting file from S3: ";
    private static final String S3_OBJECT_URL = "https://%s.s3.%s.amazonaws.com/%s";

    private static final List<String> IMAGE_TYPES = Arrays.asList("image/jpeg", "image/png", "image/gif");
    private static final List<String> VIDEO_TYPES = Arrays.asList("video/mp4", "video/mpeg", "video/quicktime");


    /**
     * Uploads a file to an Amazon S3 bucket. Based on the file type (image or video),
     * it performs image resizing and compression or video compression before uploading.
     * Files larger than 10MB are uploaded using multipart upload for better performance
     * and error resilience, while smaller files use a simple upload.
     *
     * @param file The file to be uploaded, typically an image or video.
     * @return The URL of the uploaded file in the S3 bucket.
     * @throws IOException If there's an error processing the file (such as reading input streams, compressing, etc.).
     * @throws InvalidFileTypeException If the file type is unknown or unsupported.
     * @throws CustomExceptions.S3Exception If there's an error during the upload to S3.
     */
    public String uploadFile(MultipartFile file) throws IOException {
        String fileType = determineFileType(file);
        String folder = determineFolder(fileType);
        String fileName = file.getOriginalFilename();

        // Check for valid file type
        if (fileType.equals("UNKNOWN")) {
            throw new InvalidFileTypeException("Invalid file type");
        }

        // Compress the file if it's an image or video
        byte[] inputStream = file.getInputStream().readAllBytes();
        long fileSize = file.getSize();

        if (fileType.equals(IMAGE)) {
            inputStream = resizeAndCompressImage(file);
            fileSize = inputStream.length;
        } else if (fileType.equals(VIDEO)) {
            try (InputStream videoStream = compressVideo(file)) {
                inputStream = videoStream.readAllBytes();
                fileSize = inputStream.length;
            } catch (IOException e) {
                throw new CustomExceptions.S3Exception("Error reading compressed video stream: " + e.getMessage());
            }
        }

        // Use multipart upload for large files
        if (fileSize > 10 * 1024 * 1024) { // Larger than 10MB
            return multipartUploadToS3(inputStream, folder + fileName);
        } else {
            return simpleUploadToS3(inputStream, folder + fileName, fileSize);
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


    public static String determineFolder(String fileType) {
        return switch (fileType) {
            case IMAGE -> "service_images/";
            case VIDEO -> "service_videos/";
            default -> throw new InvalidFileTypeException("Invalid file type");
        };
    }


    /**
     * Resizes and compresses an image before uploading it to Amazon S3. The image
     * is resized to a maximum width and height (800x600) while maintaining quality.
     * Compression quality is dynamically adjusted based on the file size: larger images
     * are compressed with lower quality to reduce file size.
     *
     * @param file The image file to be resized and compressed.
     * @return A byte array containing the resized and compressed image data.
     * @throws IOException If there's an error reading or writing the image data.
     */
    private byte[] resizeAndCompressImage(MultipartFile file) throws IOException {
        BufferedImage originalImage = ImageIO.read(file.getInputStream());

        // Resize the original image
        BufferedImage resizedImage = Scalr.resize(originalImage, Scalr.Method.QUALITY, 800, 600); // Adjust size as needed

        // Set compression quality based on original size
        float compressionQuality = file.getSize() > 2 * 1024 * 1024 ? 0.8f : 0.9f;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // Get a writer for JPEG format
        ImageWriter writer = ImageIO.getImageWritersByFormatName("jpeg").next();
        ImageWriteParam param = writer.getDefaultWriteParam();

        // Set compression mode to use and set the compression quality
        param.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        param.setCompressionQuality(compressionQuality);

        // Create an ImageOutputStream to write to
        try (ImageOutputStream ios = ImageIO.createImageOutputStream(outputStream)) {
            writer.setOutput(ios);
            writer.write(null, new IIOImage(resizedImage, null, null), param);
        } finally {
            writer.dispose(); // Clean up resources
        }

        return outputStream.toByteArray();
    }


    /**
     * Compresses a video file before uploading it to Amazon S3. The video compression
     * process is handled by an external tool, such as FFmpeg. The compressed video is
     * returned as an InputStream, which can then be uploaded to S3.
     *
     * @param file The video file to be compressed.
     * @return An InputStream containing the compressed video data.
     * @throws IOException If there's an error during video compression or file handling.
     * @throws CustomExceptions.S3Exception If the video compression process fails.
     */
    private InputStream compressVideo(MultipartFile file) throws IOException {
        // Create temporary files for the input and output
        File tempFile = Files.createTempFile("temp-video", ".mp4").toFile();
        file.transferTo(tempFile);

        File compressedVideo = Files.createTempFile("compressed", ".mp4").toFile();
        Process process = getProcess(tempFile, compressedVideo);

        // Wait for the process to finish in a separate thread
        CompletableFuture<Void> compressionTask = CompletableFuture.runAsync(() -> {
            try {
                process.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                try {
                    // Clean up temporary files
                    Files.delete(tempFile.toPath());
                    Files.delete(compressedVideo.toPath());
                } catch (IOException e) {
                    cleanUpTempFiles(tempFile, compressedVideo);
                }
            }
        });

        // Wait for the compression task to complete
        compressionTask.exceptionally(e -> {
            throw new CustomExceptions.S3Exception("Error during video compression: " + e.getMessage());
        }).join();

        // Return the compressed video as an InputStream
        return new FileInputStream(compressedVideo);
    }


    private static @NotNull Process getProcess(File tempFile, File compressedVideo) throws IOException {
        // Use ProcessBuilder for better handling of external processes
        ProcessBuilder processBuilder = new ProcessBuilder("ffmpeg", "-i",
                tempFile.getAbsolutePath(), "-vcodec", "libx264", "-crf", "28",
                compressedVideo.getAbsolutePath());
        processBuilder.redirectErrorStream(true); // Merge error and output streams

        return processBuilder.start();
    }

    private void cleanUpTempFiles(File tempFile, File compressedVideo) {
        try {
            Files.delete(tempFile.toPath());
            Files.delete(compressedVideo.toPath());
        } catch (IOException e) {
            // Log the error or handle it as needed
            log.error("Error deleting temporary files: {}", e.getMessage());
        }
    }

    /**
     * Uploads a file using multipart upload to Amazon S3. Multipart upload is used for large
     * files (over 10 MB), allowing the file to be split into smaller parts that are uploaded
     * separately. This method provides resilience against network failures and allows for parallel uploads.
     *
     * @param fileData The file data as a byte array.
     * @param s3Key    The key (path) under which the file will be stored in the S3 bucket.
     * @return The URL of the uploaded file in the S3 bucket.
     * @throws CustomExceptions.S3Exception If the multipart upload fails.
     */
    private String multipartUploadToS3(byte[] fileData, String s3Key) {
        CompletableFuture<PutObjectResponse> futureResponse = s3AsyncClient.putObject(
                PutObjectRequest.builder()
                        .bucket(bucketName)
                        .key(s3Key)
                        .build(),
                AsyncRequestBody.fromBytes(fileData)
        );

        try {
            futureResponse.join(); // Blocks until the upload is complete
        } catch (Exception e) {
            throw new CustomExceptions.S3Exception("Error during multipart upload: " + e.getMessage());
        }

        return String.format(S3_OBJECT_URL, bucketName, region, s3Key);
    }


    /**
     * Uploads a file to Amazon S3 using a simple (single) upload. This is used for smaller files
     * (less than 10 MB), where the entire file is uploaded in a single request. Simple uploads
     * are straightforward but less resilient to network issues compared to multipart uploads.
     *
     * @param fileData The file data as a byte array.
     * @param s3Key    The key (path) under which the file will be stored in the S3 bucket.
     * @param fileSize The size of the file in bytes.
     * @return The URL of the uploaded file in the S3 bucket.
     * @throws CustomExceptions.S3Exception If the simple upload fails.
     */
    private String simpleUploadToS3(byte[] fileData, String s3Key, long fileSize) {
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucketName)
                .key(s3Key)
                .build();
        log.info("Uploading file to S3: {} (Size: {} bytes)", s3Key, fileSize);

        try {
            s3.putObject(putObjectRequest, RequestBody.fromBytes(fileData));
        } catch (SdkException e) {
            throw new CustomExceptions.S3Exception(ERROR_DELETING_FILE + e.getMessage());
        }

        return String.format(S3_OBJECT_URL, bucketName, region, s3Key);
    }

    /**
     * Handles the deletion of a file from an S3 bucket using its URL.
     * <p>
     * This method extracts the S3 key from the file URL, streams the file to process
     * it momentarily, and then deletes it from the S3 bucket.
     *
     * @param fileUrl The full URL of the file stored in the S3.
     * @return A success message indicating the file was deleted.
     */
    public String handleFileDeletion(String fileUrl) {
        String s3Key = extractS3KeyFromUrl(fileUrl);
        try (InputStream ignored = streamFileFromS3(s3Key)) {
            return deleteFileFromS3(s3Key);
        } catch (IOException e) {
            throw new CustomExceptions.S3Exception("Error streaming file from S3: " + e.getMessage());
        } catch (SdkException e) {
            throw new CustomExceptions.S3Exception(ERROR_DELETING_FILE + e.getMessage());
        }
    }


    /**
     * Extracts the S3 key from the given file URL.
     * <p>
     * Removes the base URL consisting of the bucket name and region to isolate the key
     * that uniquely identifies the file within the bucket.
     *
     * @param fileUrl   The full URL of the file in the S3 bucket.

     * @return The extracted S3 key that identifies the file.
     */
    public String extractS3KeyFromUrl(String fileUrl) {
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
            throw new CustomExceptions.S3Exception(ERROR_DELETING_FILE + e.getMessage());
        }
    }


    public ResponseEntity<Resource> streamVideo(String fileUrl) {
        String s3Key = extractS3KeyFromUrl(fileUrl);

        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket(bucketName)
                .key(s3Key)
                .build();

        try (ResponseInputStream<GetObjectResponse> responseInputStream =
                     s3.getObject(getObjectRequest, ResponseTransformer.toInputStream())) {

            long contentLength = responseInputStream.response().contentLength();
            InputStreamResource resource = new InputStreamResource(responseInputStream);

            return ResponseEntity.status(HttpStatus.OK)
                    .header(HttpHeaders.CONTENT_TYPE, responseInputStream.response().contentType())
                    .header(HttpHeaders.CONTENT_LENGTH, String.valueOf(contentLength))
                    .body(resource);

        } catch (Exception e) {
            throw new CustomExceptions.S3Exception("Error streaming video from S3 " + e.getMessage());
        }
    }

    public List<S3ObjectResponse> listObjects() {
        ListObjectsRequest listObjectsRequest = ListObjectsRequest.builder()
                .bucket(bucketName)
                .build();

        ListObjectsResponse listObjectsResponse = s3.listObjects(listObjectsRequest);

        return listObjectsResponse.contents().stream()
                .map(s3Object -> S3ObjectResponse.builder()
                        .key(s3Object.key())
                        .etag(s3Object.eTag())
                        .size(s3Object.size())
                        .storageClass(s3Object.storageClassAsString())
                        .url(String.format(S3_OBJECT_URL, bucketName, region, s3Object.key()))
                        .build())
                .toList();

    }

}
