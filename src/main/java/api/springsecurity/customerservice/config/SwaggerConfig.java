package api.springsecurity.customerservice.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(
        info = @Info(
                title = "Customer Service Backend API",
                version = "1.0",
                description = "API documentation for the Customer Service Backend API"
        ),
        servers = {@Server(
                url = "http://localhost:9090",
                description = "Local server")
                ,@Server(
                url = "http://18.170.33.214:9090/",
                description = "Production server")
        },
        security = {
                @SecurityRequirement(
                        name = "bearerAuth"
                )
        }
)
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        in =  SecuritySchemeIn.HEADER,
        bearerFormat = "JWT",
        description = "JWT Token"
)
public class SwaggerConfig {

}
