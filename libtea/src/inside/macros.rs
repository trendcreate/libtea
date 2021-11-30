macro_rules! defer {
    ($e:expr) => {
        let _scope_call = crate::inside::structs::DeferWrapper::new(|| -> () {
            $e;
        });
    };
}
