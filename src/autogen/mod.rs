pub mod google {
    pub mod api {
        include!("google.api.rs");
    }
    pub mod bigtable {
        pub mod v2 {
            include!("google.bigtable.v2.rs");
        }
    }
    pub mod rpc {
        include!("google.rpc.rs");
    }
}
