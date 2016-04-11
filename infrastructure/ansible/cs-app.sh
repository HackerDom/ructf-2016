#!/bin/bash
[ -d .log ] || mkdir .log
git pull
ansible-playbook cs-app/playbook.yml $@
