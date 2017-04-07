# Shadowsocks port traffic collecting

Shadowsocks is able to configure multiple ports and passwords on a single instance. This program can collect traffic data for every port on shadowsocks and save the data to MySQL.

## Features

* No extra shadowsocks configuration
* Dynamically adding iptables rules and MySQL tables
* Accumulation and differential traffic data for front-end display

## Usage

* Edit config.json at your will
* Run the program periodically using something like `crontab`

        # $PATH is needed
        * * * * * source /home/yourusername/.bash_profile && sudo $GOPATH/bin/ss-port-traffic-collect config.json

## Technical explaination

### Methods

* Add iptables rules (`addrule` for short)
* Create MySQL tables (`createtable` for short)
* Calculate port traffic data (`collectdata` for short)
* Record traffic data (`savedata` for short)

In order to avoid maintaining and syncing shadowsocks configuration changes, `addrule` will check your shadowsocks config file everytime to reflect newest config status, but will *not* add duplicated rules. `createtable` will also try to create every port table if it doesn't exist.

`collectdata` will read accumulated traffic data on a certain port, but will also maintain a file that contains the traffic data last time it read, so that the differential traffic data could be calculated for better front-end display. If traffic data on a port is reset, accumulated traffic data will also be reset, but differential traffic data can continue.

### Procedures

The whole process can run concurrently, shown as follows:

        |addrule| -> |collectdata| -> |save|
        |createtable| --------------> |data|

Thanks to Golang's concurrent mechanism, the implemetation is quite simple and straghtforward.

### Table structure

The program will generate a table for every port, the structure is as follows:

        | traffic_accu | BIGINT NOT NULL DEFAULT 0                       |
        | traffic_diff | BIGINT NOT NULL DEFAULT 0                       |
        | collect_time | TIMESTAMP DEFAULT CURRENT_TIMESTAMP PRIMARY KEY |
