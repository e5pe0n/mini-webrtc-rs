use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Token};

#[proc_macro_derive(TryFromPrimitive, attributes(try_from))]
pub fn derive_try_from_primitive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = &input.ident;

    // Parse attributes to get type and error message
    let mut from_type: Option<syn::Type> = None;
    let mut error_msg: Option<String> = None;

    for attr in &input.attrs {
        if attr.path().is_ident("try_from") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("type") {
                    let _: Token![=] = meta.input.parse()?;
                    let type_str: syn::LitStr = meta.input.parse()?;
                    from_type = syn::parse_str(&type_str.value()).ok();
                } else if meta.path.is_ident("error") {
                    let _: Token![=] = meta.input.parse()?;
                    let error_str: syn::LitStr = meta.input.parse()?;
                    error_msg = Some(error_str.value());
                }
                Ok(())
            });
        }
    }

    let from_type = from_type.expect("Missing #[try_from(type = \"...\")] attribute");
    let error_msg = error_msg.unwrap_or_else(|| format!("invalid {}; {{}}", enum_name));

    // Extract enum variants and their discriminants
    let variants = match &input.data {
        Data::Enum(data_enum) => &data_enum.variants,
        _ => panic!("TryFromPrimitive can only be derived for enums"),
    };

    let match_arms = variants.iter().map(|variant| {
        let variant_name = &variant.ident;

        // Check if the variant has only unit fields
        match &variant.fields {
            Fields::Unit => (),
            _ => panic!("TryFromPrimitive only supports unit variants"),
        };

        if let Some((_, expr)) = &variant.discriminant {
            quote! {
                #expr => Ok(Self::#variant_name)
            }
        } else {
            panic!("All variants must have explicit discriminants")
        }
    });

    let expanded = quote! {
        impl TryFrom<#from_type> for #enum_name {
            type Error = String;

            fn try_from(value: #from_type) -> Result<Self, Self::Error> {
                match value {
                    #(#match_arms,)*
                    _ => Err(format!(#error_msg, value)),
                }
            }
        }
    };

    TokenStream::from(expanded)
}
