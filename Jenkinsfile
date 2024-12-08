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
        jdk 'jdk_21'
    }

    environment {
        IMAGE_NAME = 'customerservice-app'
        EC2_IP = '13.40.12.135'
        EC2_USER = 'ubuntu'
        S3_BUCKET = 'cs-pipeline'
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
                    echo "current workdir: "
                    sh 'pwd'
                    echo "Running Maven test command..."
                    runMavenCommand('test')
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    echo "Building Docker image..."
                    sh 'docker build -t ${IMAGE_NAME} .'
                }
            }
        }

        stage("Login to Docker") {
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: 'DockerHub-Access', usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                        sh "docker login -u ${DOCKER_USERNAME} -p ${DOCKER_PASSWORD}"
                    }
                }
            }
        }

        stage('Push Docker Image to DockerHub') {
            steps {
                script {
                    echo "Pushing Docker image to DockerHub..."
                    sh 'docker tag ${IMAGE_NAME} braguru/${IMAGE_NAME}'
                    sh 'docker push braguru/${IMAGE_NAME}'
                }
            }
        }

        stage('Deploy to EC2') {
            steps {
                script {
                    withCredentials([sshUserPrivateKey(credentialsId: 'ec2-ssh-key', keyFileVariable: 'SSH_KEY_PATH', usernameVariable: 'EC2_USER')]) {
                        echo "Deploying Docker container on EC2..."

                        // Create a directory and organize files
                        sh """
                        echo "Creating the 'app/' directory and copying required files..."
                        mkdir -p app/project
                        cp ./docker-compose.yml app/
                        """

                        // Transfer the directory to the EC2 instance
                        echo "Transferring deployment files to EC2..."
                        sh """
                        scp -i $SSH_KEY_PATH -o StrictHostKeyChecking=no -r app/ $EC2_USER@$EC2_IP:/tmp/
                        """

                        // Deploy using the transferred files
                        echo "Deploying Docker container on EC2..."
                        sh """
                        ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no $EC2_USER@$EC2_IP << 'EOF'
                        IMAGE_NAME=${IMAGE_NAME}

                        # Stop and remove the existing container if it exists
                        echo "Stopping and removing existing container if it exists..."
                        docker ps -q --filter "name=cs_backend_app" | grep -q . && docker stop cs_backend_app && docker rm cs_backend_app || echo "No existing container to remove."

                        #Pull the latest image
                        echo "Pulling Docker image: braguru/\$IMAGE_NAME"
                        docker pull braguru/\$IMAGE_NAME

                        cd /app/project
                        if [ -f /home/ubuntu/docker-compose.yml ]; then
                            echo "Removing old docker-compose.yml..."
                            rm /home/ubuntu/docker-compose.yml
                        fi
                        # Move deployment files to the deployment directory
                        mv /tmp/app/project/docker-compose.yml /home/ubuntu/project
                        cat /home/ubuntu/project/docker-compose.yml

                        cd /home/ubuntu/project
                        echo "Restarting services using the new docker-compose.yml..."
                        docker compose down || echo "No running services to stop."
                        # Start the app service using Docker Compose
                        echo "Starting the app service using Docker Compose..."
                        docker compose up -d
                        EOF
                        """
                    }
                }
            }
        }

        stage('Backup Jenkins to S3') {
            steps {
                script {
                    echo "Backing up Jenkins home directory to S3..."
                    sh '''
                    aws s3 cp $JENKINS_HOME ${S3_BUCKET}/jenkins-backups/ --recursive
                    '''
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline execution completed."
            script {
                echo "Starting cleanup tasks..."
                try {
                    echo "Removing Docker image"
                    sh "docker rmi ${IMAGE_NAME}"
                    echo "Pruning Docker system"
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
