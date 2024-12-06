def runMavenCommand(command) {
    def mvn = tool 'maven'
    try {
        sh "${mvn}/bin/mvn ${command}"
    } catch (Exception e) {
        echo "Maven command '${command}' failed: ${e.getMessage()}"
        throw e
    }
}

pipeline {
  agent any

      tools {
          maven 'maven'
          jdk 'jdk21'
      }

      environment {
          // Define variables
          IMAGE_NAME = 'myapp:latest'
          EC2_IP = '3.8.137.164'
          EC2_USER = 'ubuntu'
          S3_BUCKET = 's3://cs-pipeline'
          JENKINS_HOME = '/var/lib/jenkins'
          gitSha = sh(script: 'git log -n 1 --pretty=format:"%H"', returnStdout: true).trim()
      }

  stages {
     stage('Checkout Git Code') {
        steps {
          git(url: 'https://github.com/braguru/Customer-Service', branch: 'main')
        }
     }
    
     stage('Test Code') {
        steps {
            script {
                // Run unit tests
                echo "current workdir: "
                sh 'pwd'
                echo "Running Maven test command..."
                runMavenCommand('test')
                sh 'mvn test'
                echo "Maven test command executed successfully."
            }
        }
     }

     stage('Build Docker Image') {
         steps {
             script {
                 // Build the Docker image
                 echo "Building Docker image..."
                 sh 'docker build -t ${IMAGE_NAME} .'
             }
         }
     }

      stage('Deploy to EC2') {
          steps {
              script {
                  // Push Docker image to DockerHub (optional)
                  echo "Pushing Docker image to DockerHub..."
                  sh 'docker tag $IMAGE_NAME braguru/$IMAGE_NAME'
                  sh 'docker push braguru/$IMAGE_NAME'
                  echo "Docker image pushed to DockerHub."

                  // Deploy the Docker container on EC2
                  echo "Deploying Docker container on EC2..."
                  sh '''
                  ssh -o StrictHostKeyChecking=no $EC2_USER@$EC2_IP << EOF
                      docker pull braguru/$IMAGE_NAME
                      docker run -d --name myapp -p 8080:8080 braguru/$IMAGE_NAME
                  EOF
                  '''
                   echo "Docker container deployed on EC2."
              }
          }
      }

      // Stage 5: Backup Jenkins Server to S3
      stage('Backup Jenkins to S3') {
          steps {
              script {
                  echo "Backup Jenkins home directory to S3..."
                  // Backup Jenkins home directory to S3
                  sh '''
                  aws s3 cp $JENKINS_HOME s3://$S3_BUCKET/jenkins-backups/ --recursive
                  '''
              }
          }
      }

  post {
        always {
              echo "Pipeline execution completed."
              script {
                    echo "Starting cleanup tasks..."
                    try {
                      echo "Removing Docker images for changed services: ${changedServices.join(', ')}"
                      changedServices.each { service ->
                      sh "docker rmi ${imageRegistry}/${imageName}:${service}-${gitSha}"
                      echo "Removed image: ${imageRegistry}/${imageName}:${service}-${gitSha}"
                      }
                      sh 'docker system prune -f'
                      cleanWs()
                    } catch (Exception e) {
                      echo "Cleanup failed: ${e.getMessage()}"
                    }
              }
        }
      success {
          echo 'Pipeline executed successfully.'
      }
      failure {
          echo 'Pipeline execution failed.'
      }
  }
  }
}