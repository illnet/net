use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Fields, Lit, Meta, MetaNameValue, Path,
    parse_macro_input, parse_str,
};

#[proc_macro_derive(VersionedPacket, attributes(pvn, packet_id, packet_crate))]
pub fn derive_versioned_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_derive(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

struct PvnAttr {
    range: proc_macro2::TokenStream,
}

struct PacketAttr {
    id: i32,
    crate_path: Path,
}

fn extract_packet_attr(input: &DeriveInput) -> Result<PacketAttr, syn::Error> {
    let mut id = None;
    let mut crate_path: Option<Path> = None;

    for attr in &input.attrs {
        if attr.path().is_ident("packet_id") {
            if let Meta::NameValue(MetaNameValue { value, .. }) = &attr.meta {
                if let syn::Expr::Lit(el) = value {
                    if let Lit::Int(ref lit) = el.lit {
                        id = Some(lit.base10_parse::<i32>()?);
                    }
                }
            }
        }
        if attr.path().is_ident("packet_crate") {
            if let Meta::NameValue(MetaNameValue { value, .. }) = &attr.meta {
                if let syn::Expr::Path(ep) = value {
                    crate_path = Some(ep.path.clone());
                }
            }
        }
    }

    let id = id.ok_or_else(|| {
        syn::Error::new_spanned(input, "missing #[packet_id = ...] attribute")
    })?;

    let crate_path = crate_path.unwrap_or_else(|| parse_str("crate").unwrap());

    Ok(PacketAttr { id, crate_path })
}

fn extract_pvn_attr(attrs: &[syn::Attribute]) -> Option<PvnAttr> {
    for attr in attrs {
        if attr.path().is_ident("pvn") {
            let tokens = &attr.meta.require_list().ok()?.tokens;
            // Parse the range expression (e.g., 766.., ..766, 759..766)
            if let Ok(expr) = parse_str::<proc_macro2::TokenStream>(&tokens.to_string()) {
                return Some(PvnAttr { range: expr });
            }
        }
    }
    None
}

fn expand_derive(input: &DeriveInput) -> Result<proc_macro2::TokenStream, syn::Error> {
    let packet = extract_packet_attr(input)?;
    let name = &input.ident;
    let id = packet.id;
    let crate_path = &packet.crate_path;

    // Extract lifetime if present
    let has_lifetime = input.generics.lifetimes().next().is_some();
    let lifetime = input.generics.lifetimes().next().map(|l| &l.lifetime);

    let (decode_stmts, encode_stmts, field_names): (
        Vec<proc_macro2::TokenStream>,
        Vec<proc_macro2::TokenStream>,
        Vec<proc_macro2::Ident>,
    ) = match &input.data {
        Data::Struct(ds) => match &ds.fields {
            Fields::Named(nf) => {
                let mut dec = Vec::new();
                let mut enc = Vec::new();
                let mut names = Vec::new();
                for field in &nf.named {
                    let field_name = field.ident.as_ref().unwrap();
                    let field_ty = &field.ty;
                    let pvn = extract_pvn_attr(&field.attrs);
                    names.push(field_name.clone());
                    if let Some(pvn) = pvn {
                        let range = &pvn.range;
                        dec.push(quote! {
                            let #field_name: #field_ty = if (#range).contains(&protocol_version) {
                                <#field_ty as #crate_path::mc::FieldRead>::read_field(input)?
                            } else {
                                ::core::default::Default::default()
                            };
                        });
                        enc.push(quote! {
                            if (#range).contains(&protocol_version) {
                                <#field_ty as #crate_path::mc::FieldWrite>::write_field(&self.#field_name, out)?;
                            }
                        });
                    } else {
                        dec.push(quote! {
                            let #field_name: #field_ty = <#field_ty as #crate_path::mc::FieldRead>::read_field(input)?;
                        });
                        enc.push(quote! {
                            <#field_ty as #crate_path::mc::FieldWrite>::write_field(&self.#field_name, out)?;
                        });
                    }
                }
                (dec, enc, names)
            }
            Fields::Unit => (Vec::new(), Vec::new(), Vec::new()),
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "VersionedPacket only supports structs with named or no fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "VersionedPacket only supports structs",
            ))
        }
    };

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let decode_sig = if has_lifetime {
        let lt = lifetime.as_ref().unwrap();
        quote! {
            pub fn decode_body_with_version(
                input: &mut & #lt [u8],
                protocol_version: i32,
            ) -> #crate_path::mc::Result<Self>
        }
    } else {
        quote! {
            pub fn decode_body_with_version(
                input: &mut &[u8],
                protocol_version: i32,
            ) -> #crate_path::mc::Result<Self>
        }
    };

    let encode_sig = quote! {
        pub fn encode_body_with_version(
            &self,
            out: &mut Vec<u8>,
            protocol_version: i32,
        ) -> #crate_path::mc::Result<()>
    };

    let result = quote! {
        impl #impl_generics #name #ty_generics #where_clause {
            pub const ID: i32 = #id;

            #decode_sig {
                #(#decode_stmts)*
                Ok(Self {
                    #(#field_names),*
                })
            }

            #encode_sig {
                #(#encode_stmts)*
                Ok(())
            }
        }
    };

    Ok(result)
}
