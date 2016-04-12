#!/bin/bash
[ -d .log ] || mkdir .log
ansible-playbook cs-requirements/playbook.yml $@
