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
        EC2_IP = '35.179.159.222'
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
                    sh 'ls -la'
                    echo "Running Maven test command..."
                    runMavenCommand('test')
                }
            }
        }

        stage('Sonarqube Analysis'){
            steps{
                script{
                    def mvn = tool 'maven'
                    withSonarQubeEnv('sonarqube') {
                        sh "${mvn}/bin/mvn clean verify sonar:sonar -Dsonar.projectKey=braguru_CS-Demo_AZPPouVVfAW3N3bdNPmg -Dsonar.projectName='CS-Demo'"
                    }
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

                        // Transfer updated docker-compose.yml to the EC2 instance
                        sh """
                        echo "Transferring updated docker-compose.yml to EC2..."
                        echo "Displaying compose file"
                        echo "current workdir: "
                        pwd
                        cat docker-compose.yml
                        scp -i $SSH_KEY_PATH -o StrictHostKeyChecking=no docker-compose.yml $EC2_USER@$EC2_IP:/home/ubuntu/project/docker-compose.yml
                        """

                        // Deploy on EC2
                        echo "Executing deployment on EC2..."
                        sh """
                        ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no $EC2_USER@$EC2_IP << 'EOF'
                        IMAGE_NAME=${IMAGE_NAME}

                        # Pull the latest image
                        echo "Pulling Docker image: braguru/\$IMAGE_NAME..."
                        docker pull braguru/\$IMAGE_NAME

                        # Navigate to the deployment directory

                        # Restart the app service using Docker Compose
                        echo "Restarting services with updated docker-compose.yml..."
                        cd /home/ubuntu/project
                        docker compose up app -d
                        """
                    }
                }
            }
        }

//         stage('Backup Jenkins to S3') {
//             steps {
//                 script {
//                     def backupDir = '/home/jenkins/backups'
//                     def jenkinsHome = '/var/lib/jenkins'
//                     def timestamp = new Date().format("yyyyMMddHHmmss")
//                     def backupFile = "jenkins_backup_${timestamp}.tar.gz"
//                     def tempBackupDir = '/home/jenkins/temp_backup'
//
//                     sh "sudo cp -r ${jenkinsHome}/workspace/* ${tempBackupDir}/"
//
//                     sh "sudo tar --ignore-failed-read  -czvf ${backupDir}/${backupFile} -C ${tempBackupDir} ."
//                     echo "Backing up Jenkins home directory to S3..."
//
//                     withAWS(credentials: 'aws-access', region: 'eu-west-2'){
//                         echo "Uploading Jenkins home directory to S3..."
//                         s3Upload(bucket: S3_BUCKET, file: "${backupDir}/${backupFile}")
//                     }
//                 }
//             }
//         }
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
            echo 'Pipeline executed successfully. 👌'
        }
        failure {
            echo 'Pipeline execution failed. 😒'
        }
    }
}
