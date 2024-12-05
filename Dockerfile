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
RUN addgroup -S cs-backend-appgroup && adduser -S cs-backend-appuser -G cs-backend-appgroup

# Set working directory inside the container
WORKDIR /app

#COPY --from=build /app/.env .
# Copy the built jar file from the build stage
COPY --from=build /app/target/*.jar app.jar

# Change ownership of the /app directory to the non-root user
RUN chown -R cs-backend-appuser:cs-backend-appgroup /app

# Switch to non-root user
USER cs-backend-appuser

# Expose the port the application runs on
EXPOSE 9090

# Command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]

# Security hardening
# Limit container memory and CPU usage in the Docker run command:
# docker run --memory="512m" --cpus="1" <image>

# Optionally add runtime security settings:
# docker run --cap-drop=ALL --read-only <image>