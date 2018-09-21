pipeline {
  agent {
    label 'prodsec' 
  }
   
  tools {
    nodejs '8.9.1'
  }

  environment {
    NPM_TOKEN = credentials('auth0npm-npm-token')
  }

  options {
    timeout(time: 10, unit: 'MINUTES') 
  }
 
  stages {
    stage('Build') { 
      steps {
        sh 'npm install --build-from-source'
        lastPublishedVersion = sh(script: 'npm view auth0-magic version', returnStdout: true).trim()
        currentVersion = sh(script: 'node -e \'console.log(require("./package.json").version)\'', returnStdout: true).trim()
      }
    }

    stage('Test') {
      steps {
        sh 'npm run test'
      }
    }

    stage('Deploy') {
      when { not { equals expected: lastPublishedVersion, actual: currentVersion }
      steps {
        sh "echo //registry.npmjs.org/:_authToken=${env.NPM_TOKEN} > .npmrc"
        sh "npm publish"
      }
    }
  }
   
  post {
    always{
      deleteDir()
    }
  }
}
