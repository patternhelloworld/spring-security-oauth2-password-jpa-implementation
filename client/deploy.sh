#!/bin/bash
local_maven_repo='/mnt/c/Users/Andrew\sKang/.m2/repository/com/patternhelloworld/securityhelper/oauth2/spring-oauth2-easyplus'
mvn  -DaltDeploymentRepository=snapshot-repo::default::file://${local_maven_repo}/snapshots clean deploy

