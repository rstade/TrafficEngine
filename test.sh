#!/bin/bash
sudo ip addr add 192.168.222.3/24 dev enp7s0f1

set -e

if [ $# -ge 1 ]; then
    TASK=$1
else
    TASK=all
fi

case $TASK in
    test_tcp_proxy)
        export RUST_LOG="tcp_proxy=info,test_tcp_proxy=info,e2d2=info"
        executable=`cargo test $2 --no-run --message-format=json --test test_tcp_proxy | jq -r 'select((.profile.test == true) and (.target.name == "test_tcp_proxy")) | .filenames[]'`
        echo $executable
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    timeout)
        export RUST_BACKTRACE=1
        export RUST_LOG="tcp_proxy=info,timeout=info,e2d2=info"
        executable=`cargo test $2 --no-run --message-format=json --test timeout | jq -r 'select((.profile.test == true) and (.target.name == "timeout")) | .filenames[]'`
        echo $executable
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    client_syn_fin)
        export RUST_LOG="tcp_proxy=info,client_syn_fin=info,e2d2=info"
        executable=`cargo test $2 --no-run --message-format=json --test client_syn_fin | jq -r 'select((.profile.test == true) and (.target.name == "client_syn_fin")) | .filenames[]'`
        echo $executable
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    all)
        ./test.sh test_tcp_proxy $2
        ./test.sh timeout $2
        ./test.sh client_syn_fin $2
        ;;



esac



