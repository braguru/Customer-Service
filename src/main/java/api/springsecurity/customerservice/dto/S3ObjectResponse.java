package api.springsecurity.customerservice.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class S3ObjectResponse {
    private String key;
    private String etag;
    private long size;
    private String storageClass;
    private String url;
}
