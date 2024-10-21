pipeline {
  agent any
  stages {

    stage('Checkout Git Code') {
      steps {
        git(url: 'https://github.com/braguru/Customer-Service', branch: 'main')
      }
    }

    stage('Run sh command') {
      steps {
        script {
          sh 'echo "Hello World"'
        }
      }
    }

  }
}