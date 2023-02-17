pub mod google {
    pub mod api {
        include!("google.api.rs");
    }
    pub mod bigtable {
        pub mod admin {
            pub mod v2 {
                include!("google.bigtable.admin.v2.rs");
            }
        }
        pub mod v2 {
            include!("google.bigtable.v2.rs");
        }
    }
    pub mod iam {
        pub mod v1 {
            include!("google.iam.v1.rs");
        }
    }
    pub mod longrunning {
        include!("google.longrunning.rs");
    }
    pub mod r#type {
        include!("google.r#type.rs");
    }
    pub mod rpc {
        include!("google.rpc.rs");
    }
}
