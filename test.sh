#!/bin/bash
sudo ip addr add 192.168.222.3/24 dev enp7s0f1

set -e

if [ $# -ge 1 ]; then
    TASK=$1
else
    TASK=all
fi

case $TASK in
    test_connect)
        export RUST_LOG="traffic_lib=info,test_connect=debug,e2d2=info", RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_connect | jq -r 'select((.profile.test == true) and (.target.name == "test_connect")) | .filenames[]'`
        echo $executable
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    all)
        ./test.sh test_connect $2
        ;;



esac



