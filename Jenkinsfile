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
                    withCredentials([usernamePassword(credentialsId: 'ec2-ssh-key', usernameVariable: 'USERNAME', passwordVariable: 'TOKEN')]) {
                        echo "Deploying Docker container on EC2..."
                        sh """
                        ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no $EC2_USER@$EC2_IP << 'EOF'
                        IMAGE_NAME=${IMAGE_NAME}
                        echo "Pulling Docker image: braguru/\$IMAGE_NAME"
                        docker pull braguru/\$IMAGE_NAME
                        echo "Running Docker container..."
                        docker run -d --name customerservice -p 9090:9090 braguru/\$IMAGE_NAME:latest
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
