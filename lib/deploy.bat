@echo off
set local_maven_repo="C:\Users\Andrew Kang\.m2\repository\com\patternknife\securityhelper\oauth2\spring-security-oauth2-password-jpa-implementation"
mvnw.cmd -DaltDeploymentRepository=snapshot-repo::default::file://%local_maven_repo%/snapshots clean deploy