#!/bin/bash -x

apt-get install libdumbnet1 libdumbnet-dev libnet1-dev libpcap-dev

sh scripts/psql.sh

apt-get install postgresql-9.3 pgadmin3

apt-get install libpq-dev

apt-get install wireshark

apt-get install libssh-dev

echo "Starting to build database environment..."
sh scripts/postgres_env.sh > /dev/null
echo "Database environment created successfully."

sudo sed -i '/icmp.h/d' /usr/include/dumbnet.h
