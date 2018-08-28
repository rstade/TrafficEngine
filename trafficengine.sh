#!/bin/bash
sudo ip addr add 192.168.222.3/24 dev enp7s0f1
export RUST_BACKTRACE=1
export RUST_LOG="traffic_lib=info,trafficengine=debug,e2d2=info"
executable=`cargo build $1 --message-format=json | jq -r 'select((.profile.test == false) and (.target.name == "trafficengine")) | .filenames[]'`
echo $executable
sudo -E env "PATH=$PATH" $executable traffic_run.toml

