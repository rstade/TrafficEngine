error_chain! {
    errors {
        MandatoryParameterMiss(param: String) {
            description("mandatory parameter missing")
            display("missing: parameter {}", param)
        }
    }

    links {
        NetBricks(::e2d2::common::Error, ::e2d2::common::ErrorKind) #[cfg(unix)];
    }

    foreign_links {
        Io(::std::io::Error);
        Toml(::toml::de::Error);
        Eui48(::eui48::ParseError);
        Ipnet(::ipnet::AddrParseError);
    }
}
