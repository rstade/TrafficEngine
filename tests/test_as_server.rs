extern crate traffic_lib;

use traffic_lib::run_test::{ run_test, TestType};

#[test]
fn test_as_server() {
    run_test(TestType::Server);
}