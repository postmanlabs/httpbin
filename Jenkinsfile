pipeline {
	agent any
    stages {
        stage('Clone Repository') {
            steps {
                checkout scm
            }
        }

        stage('Testing Prerequisite'){
            steps {
                sh 'sudo pip3 install pipenv'
                // sh 'pipenv shell' 
                sh 'pipenv install --ignore-pipfile'
            }
        }

        stage('Unit Testing'){
            steps {
                sh 'pipenv shell'
                sh 'python test_httpbin.py'
            }
        }

        // stage('Build Image') {
        //     steps {
        //         sh 'sudo docker build -t jdtest:v1.0 .'
        //     }
        // }

        // stage('Run Image') {
        //     steps {
        //         sh 'sudo docker run -d -p 80:5000 --name jd jdtest:v1.0'
        //     }
        // }
    }
}