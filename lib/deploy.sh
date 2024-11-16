#!/bin/bash
local_maven_repo='/mnt/c/Users/Andrew\sKang/.m2/repository/com/patternknife/securityhelper/oauth2/spring-security-oauth2-password-jpa-implementation'
mvn  -DaltDeploymentRepository=snapshot-repo::default::file://${local_maven_repo}/snapshots clean deploy

