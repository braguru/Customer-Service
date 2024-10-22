FROM maven:3.9.9-eclipse-temurin-21-alpine AS build

WORKDIR /app

# Copy only the necessary files for downloading dependencies
COPY pom.xml .

# Download dependencies (cached if no changes in pom.xml)
RUN mvn dependency:go-offline

# Copy the entire source code
COPY src ./src
COPY .env .

# Build the application
RUN mvn clean package -DskipTests

# Step 2: Runtime stage
FROM eclipse-temurin:21-jdk-alpine

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory inside the container
WORKDIR /app

COPY --from=build /app/.env .
# Copy the built jar file from the build stage
COPY --from=build /app/target/myapp.jar /app/myapp.jar

# Change ownership of the /app directory to the non-root user
RUN chown -R ccp-backend-appuser:ccp-backend-appgroup /app

# Switch to non-root user
USER appuser

# Expose the port the application runs on
EXPOSE 9090

# Command to run the application
ENTRYPOINT ["java", "-jar", "/app/myapp.jar"]

# Security hardening
# Limit container memory and CPU usage in the Docker run command:
# docker run --memory="512m" --cpus="1" <image>

# Optionally add runtime security settings:
# docker run --cap-drop=ALL --read-only <image>