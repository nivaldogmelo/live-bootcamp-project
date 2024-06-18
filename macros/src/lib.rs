extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn test_and_cleanup(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    let test_name = &input.sig.ident;
    let block = &input.block;

    let output = quote! {
    #[tokio::test]
    async fn #test_name() {
    let mut app = TestApp::new().await;
    #block
    app.clean_up().await;
    }
    };

    output.into()
}
