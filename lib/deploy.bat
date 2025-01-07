@echo off
set local_maven_repo="C:\Users\Andrew Kang\.m2\repository\com\patternhelloworld\securityhelper\oauth2\spring-oauth2-easyplus"
mvnw.cmd -DaltDeploymentRepository=snapshot-repo::default::file://%local_maven_repo%/snapshots clean deploy