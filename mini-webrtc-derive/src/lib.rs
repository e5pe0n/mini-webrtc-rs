use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Token};

#[proc_macro_derive(TryFromPrimitive, attributes(try_from))]
pub fn derive_try_from_primitive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = &input.ident;

    // Parse attributes to get type
    let mut from_type: Option<syn::Type> = None;

    for attr in &input.attrs {
        if attr.path().is_ident("try_from") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("type") {
                    let _: Token![=] = meta.input.parse()?;
                    let type_str: syn::LitStr = meta.input.parse()?;
                    from_type = syn::parse_str(&type_str.value()).ok();
                }
                Ok(())
            });
        }
    }

    let from_type = from_type.expect("Missing #[try_from(type = \"...\")] attribute");

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
            type Error = crate::error::Error;

            fn try_from(value: #from_type) -> Result<Self, Self::Error> {
                match value {
                    #(#match_arms,)*
                    _ => Err(crate::error::Error::InvalidEnumVariantError {
                        enum_name: stringify!(#enum_name).to_string(),
                        value: format!("{:?}", value),
                    }),
                }
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(FromPrimitive, attributes(from))]
pub fn derive_from_primitive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = &input.ident;

    // Parse attributes to get type and default variant
    let mut from_type: Option<syn::Type> = None;
    let mut default_variant: Option<syn::Ident> = None;

    for attr in &input.attrs {
        if attr.path().is_ident("from") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("type") {
                    let _: Token![=] = meta.input.parse()?;
                    let type_str: syn::LitStr = meta.input.parse()?;
                    from_type = syn::parse_str(&type_str.value()).ok();
                } else if meta.path.is_ident("default") {
                    let _: Token![=] = meta.input.parse()?;
                    let default_str: syn::LitStr = meta.input.parse()?;
                    default_variant = syn::parse_str(&default_str.value()).ok();
                }
                Ok(())
            });
        }
    }

    let from_type = from_type.expect("Missing #[from(type = \"...\")] attribute");
    let default_variant = default_variant.expect("Missing #[from(default = \"...\")] attribute");

    // Extract enum variants and their discriminants
    let variants = match &input.data {
        Data::Enum(data_enum) => &data_enum.variants,
        _ => panic!("FromPrimitive can only be derived for enums"),
    };

    let match_arms = variants.iter().map(|variant| {
        let variant_name = &variant.ident;

        // Check if the variant has only unit fields
        match &variant.fields {
            Fields::Unit => (),
            _ => panic!("FromPrimitive only supports unit variants"),
        };

        if let Some((_, expr)) = &variant.discriminant {
            quote! {
                #expr => Self::#variant_name
            }
        } else {
            panic!("All variants must have explicit discriminants")
        }
    });

    let expanded = quote! {
        impl From<#from_type> for #enum_name {
            fn from(value: #from_type) -> Self {
                match value {
                    #(#match_arms,)*
                    _ => Self::#default_variant,
                }
            }
        }
    };

    TokenStream::from(expanded)
}
