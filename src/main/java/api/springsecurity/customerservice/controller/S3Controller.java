package api.springsecurity.customerservice.controller;

import api.springsecurity.customerservice.dto.S3ObjectResponse;
import api.springsecurity.customerservice.utils.S3Util;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/s3")
public class S3Controller {

    private final S3Util s3Util;

    @GetMapping("/stream-video")
    public ResponseEntity<Resource> streamVideo(@RequestParam String fileUrl) {
        return s3Util.streamVideo(fileUrl);
    }

    @GetMapping("objects")
    public ResponseEntity<List<S3ObjectResponse>> listS3Objects() {
        return ResponseEntity.ok(s3Util.listObjects());
    }

    @GetMapping(value = "/object-content", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> getObjectContent() throws IOException {
        byte[] data = s3Util.getObject();
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(data);
    }

    @GetMapping("/object-url")
    public String getObjectPresignedUrl(@RequestParam String key) {
        return s3Util.generatePresignedUrl(key);
    }
}
