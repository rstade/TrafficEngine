#!/bin/bash
#we flush the ARP cache because outdated ARP entries may let tests fail
#sudo ip -s -s neigh flush all
export RUST_BACKTRACE=1
export RUST_LOG="traffic_lib=info,trafficengine=info,e2d2=info,netfcts=info"
executable=`cargo build $2 --message-format=json | jq -r 'select((.profile.test == false) and (.target.name == "trafficengine")) | .filenames[]'`
echo $executable
sudo -E env "PATH=$PATH" $executable $1
