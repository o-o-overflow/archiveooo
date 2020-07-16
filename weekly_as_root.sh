#!/bin/sh

systemctl stop apache2

docker ps --all -q | xargs --no-run-if-empty docker rm -f >/dev/null
docker images -q | xargs --no-run-if-empty docker rmi -f >/dev/null
docker network prune -f >/dev/null
docker volume prune -f >/dev/null

systemctl start apache2
