#!/bin/bash -x


chmod 777 postgres_env.sh

sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'postgres';"

sudo -u postgres psql -c "CREATE DATABASE bubble";

sudo -u postgres psql -d bubble -c "CREATE TABLE ike (test_id serial NOT NULL, type_of_packet char(20), type_of_problem char(48), os_version_device char(124), comment char(64), binary_pack_data varchar(32100) NOT NULL UNIQUE, binary_diff_data VARCHAR(32100), misc_description char(3), PRIMARY KEY (test_id))";

sudo -u postgres psql -d bubble -c "CREATE TABLE arp (test_id serial NOT NULL, type_of_packet char(20), type_of_problem char(48), os_version_device char(124), comment char(64), binary_pack_data varchar(32100) NOT NULL UNIQUE, binary_diff_data VARCHAR(32100), misc_description char(3), PRIMARY KEY (test_id))";

sudo -u postgres psql -d bubble -c "CREATE TABLE bgp (test_id serial NOT NULL, type_of_packet char(20), type_of_problem char(48), os_version_device char(124), comment char(64), binary_pack_data varchar(32100) NOT NULL UNIQUE, binary_diff_data VARCHAR(32100), misc_description char(3), PRIMARY KEY (test_id))";

sudo -u postgres psql -d bubble -c "CREATE TABLE msdp (test_id serial NOT NULL, type_of_packet char(20), type_of_problem char(48), os_version_device char(124), comment char(64), binary_pack_data varchar(32100) NOT NULL UNIQUE, binary_diff_data VARCHAR(32100), misc_description char(3), PRIMARY KEY (test_id))";

sudo -u postgres psql -d bubble -c "CREATE TABLE dhcp (test_id serial NOT NULL, type_of_packet char(20), type_of_problem char(48), os_version_device char(124), comment char(64), binary_pack_data varchar(32100) NOT NULL UNIQUE, binary_diff_data VARCHAR(32100), misc_description char(3), PRIMARY KEY (test_id))";

sudo -u postgres psql -d bubble -c "CREATE TABLE dns (test_id serial NOT NULL, type_of_packet char(20), type_of_problem char(48), os_version_device char(124), comment char(64), binary_pack_data varchar(32100) NOT NULL UNIQUE, binary_diff_data VARCHAR(32100), misc_description char(3), PRIMARY KEY (test_id))";

sudo -u postgres psql -d bubble -c "INSERT INTO arp_sample (test_id, type_of_packet, type_of_problem, os_version_device, comment, binary_pack_data) values (1, 'arp broadcast', 'sample', 'none', 'sample', 'ff|ff|ff|ff|ff|ff|00|50|56|99|1f|c3|08|06|00|01|08|00|06|04|00|01|00|50|56|99|1f|c3|a9|fe|ef|40|00|00|00|00|00|00|0a|30|3e|81|00|00|00|00|00|00|00|00|00|00|00|00|00|00|00|00|00|00|')";

