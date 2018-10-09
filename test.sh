#!/bin/bash
sudo ip addr add 192.168.222.3/24 dev enp7s0f1

set -e

if [ $# -ge 1 ]; then
    TASK=$1
else
    TASK=all
fi

case $TASK in
    test_as_client)
        export RUST_LOG="traffic_lib=debug,test_as_client=debug,e2d2=info", RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_as_client | jq -r 'select((.profile.test == true) and (.target.name == "test_as_client")) | .filenames[]'`
        echo $executable
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    test_as_server)
        export RUST_LOG="traffic_lib=debug,test_as_server=debug,e2d2=info", RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_as_server | jq -r 'select((.profile.test == true) and (.target.name == "test_as_server")) | .filenames[]'`
        echo $executable
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;

    all)
        ./test.sh test_as_client $2
        ./test.sh test_as_server $2
        ;;



esac



