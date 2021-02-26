pipeline {
	agent any
    stages {
        // Gets the latest source code from the SCM
        stage('Clone Repository') {
            steps {
                checkout scm
            }
        }

        // // Installs all the prerequisites needed for the unit test
        // stage('Install Test Prerequisites'){
        //     steps {
        //         sh 'sudo pip3 install pipenv'
        //         sh 'pipenv install --ignore-pipfile'
        //     }
        // }

        // // Performs unit testing
        // stage('Unit Test'){
        //     steps {
        //         sh 'pipenv run python test_httpbin.py'
        //     }
        // }

        // Builds Docker Image
        stage('Build Image') {
            steps {
                sh "sudo docker build -t jdtest:\"${BUILD_ID}\" ."
            }
        }

        // Deploys the image as container
        stage('Run Image') {
            steps {
                script{
                    // Get last successful build ID
                    def SUCCESS_BUILD = 0
                    def build = currentBuild.previousBuild
                    while (build != null) {
                        if (build.result == "SUCCESS")
                        {
                            SUCCESS_BUILD = build.id as Integer
                            break
                        }
                        build = build.previousBuild
                    }

                    // Stop and remove previous container
                    sh "sudo docker rm -f jd-\"${SUCCESS_BUILD}\" && echo \"container ${SUCCESS_BUILD} removed\" || echo \"container ${SUCCESS_BUILD} does not exist\""
                    sh 'sudo docker system prune'

                    // Run latest container
                    sh "sudo docker run -d -p 5000:80 --name jd-\"${BUILD_ID}\" jdtest:\"${BUILD_ID}\""

                }
            }
        }
    }
}