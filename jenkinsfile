node {
   def commit_id
   stage('Preparation') {
     checkout scm
     sh "git rev-parse --short HEAD > .git/commit-id"                        
     commit_id = readFile('.git/commit-id').trim()
   }
 
   stage('docker build/push') {
     docker.withRegistry('https://index.docker.io/v2/', 'dockerhub') {
       def app = docker.build("yugant1/docker-nodejs-demo", '.').push()
     }
   }
   stage('deploy')  {
       sh """
       docker run -p 3000:3000 -d --name my-nodejs-app yugant1/docker-nodejs-demo
       """
     
     }
   
}
