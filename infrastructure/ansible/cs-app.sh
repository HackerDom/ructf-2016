#!/bin/bash
[ -d .log ] || mkdir .log
git -C ../../../checksystem/ pull
git pull
ansible-playbook cs-app/playbook.yml $@
