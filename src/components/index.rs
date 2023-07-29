use leptos::{component, ssr::render_to_string, view, IntoAttribute, IntoView, Scope};

use crate::models::Profile;

pub fn page_index(profile: Option<Profile>) -> String {
    render_to_string(|cx| {
        view! {cx,
            <html>
                <div>Welcome to the oidc-auth-demo!</div>
                <ProfileCard profile=profile />
                <a href="/auth/oidc/google">Login</a>
            </html>
        }
    })
}

#[component]
pub fn ProfileCard(cx: Scope, profile: Option<Profile>) -> impl IntoView {
    match profile {
        Some(inner) => view! { cx,
            <div>
                <img src=inner.picture_url />
                <p>Name: {inner.name}</p>
                <p>Email: {inner.email}</p>
            </div>
        },
        None => view! { cx,
            <div>
                (not logged in)
            </div>
        },
    }
}
