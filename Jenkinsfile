pipeline {
	agent any
    stages {
        // Gets the latest source code from the SCM
        stage('Clone Repository') {
            steps {
                checkout scm
            }
        }

        // Installs all the prerequisites needed for the unit test
        stage('Install Test Prerequisites'){
            steps {
                sh 'sudo pip3 install pipenv'
                sh 'pipenv install --ignore-pipfile'
            }
        }

        // Performs unit testing
        stage('Unit Test'){
            steps {
                sh 'pipenv run python test_httpbin.py'
            }
        }

        // Builds Docker Image
        stage('Build Image') {
            steps {
                sh 'sudo docker build -t jdtest:v1.0 .'
            }
        }

        // Deploys the image as container
        stage('Run Image') {
            steps {
                // Stop and remove previous container
                sh 'sudo docker stop jd'
                sh 'sudo docker container rm jd'
                sh 'sudo docker run -d -p 5000:80 --name jd jdtest:v1.0'
            }
        }
    }
}