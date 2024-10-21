pipeline {
  agent {label 'agent1'}
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