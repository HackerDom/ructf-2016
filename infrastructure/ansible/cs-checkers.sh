#!/bin/bash
[ -d .log ] || mkdir .log
git pull
ansible-playbook cs-checkers/playbook.yml $@
