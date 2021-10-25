pipeline { 
    environment {
    registry = "sitaramreddy/kalyan-dockerdeploy"
    registryCredential = 'dockerhub'
    dockerImage = ''
  }  
  agent any  
  stages {
      stage('Cloning Git') {
          steps {
             git 'https://github.com/postmanlabs/httpbin.git'
           }
 }
    stage('Building image') {
      steps{
        script {
          dockerImage = docker.build registry + ":$BUILD_NUMBER"
        }
      }
    }
    stage('Deploy Image') {
      steps{
        script {
          docker.withRegistry( '', registryCredential ) {
            dockerImage.push()
          }
        }
      }
    }
    stage('Remove Unused docker image') {
      steps{
        sh "docker rmi $registry:$BUILD_NUMBER"
      }
    }
   }
  }
