#!/bin/bash

# Graceful Shutdown
#trap exitHandler EXIT
#exitHandler() {
 #   echo "[INSIDE APP CONTAINER][WARN] Server will be shutdown soon." 1>&2
  #  kill -TERM $(jps | grep jar | awk '{print $1}')
#}

if [ -z "$1" ]; then
    echo "[INSIDE APP CONTAINER][ERROR] No project root path parameter found for the 'run-app.sh'"
    exit 1
fi
if [ -z "$2" ]; then
    echo "[INSIDE APP CONTAINER][ERROR] No file root path parameter found for the 'run-app.sh'"
    exit 1
fi
if [ -z "$3" ]; then
    echo "[INSIDE APP CONTAINER][ERROR] No Xms parameter found for the 'run-app.sh'"
    exit 1
fi
if [ -z "$4" ]; then
    echo "[INSIDE APP CONTAINER][ERROR] No Xmx parameter found for the 'run-app.sh'"
    exit 1
fi

echo "[INSIDE APP CONTAINER][NOTICE] Run : java -Xms${3}m -Xmx${4}m -XX:+PrintGCDetails -Xloggc:${2}/logs/auth-gc.log -Dspring.config.location=file:${1}/src/main/resources/application.properties -Dlogging.config=file:${1}/src/main/resources/logback-spring.xml -jar /app.jar > ${2}/logs/auth-start.log 2>&1 &"
java -XX:+PrintGCDetails -Xms${3}m -Xmx${4}m -Xloggc:${2}/logs/auth-gc.log -Dspring.config.location=file:${1}/src/main/resources/application.properties -Dlogging.config=file:${1}/src/main/resources/logback-spring.xml -jar /app.jar > ${2}/logs/auth-start.log 2>&1 &
