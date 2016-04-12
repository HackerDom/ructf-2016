#!/bin/bash
[ -d .log ] || mkdir .log
ansible-playbook cs-app/playbook.yml $@
