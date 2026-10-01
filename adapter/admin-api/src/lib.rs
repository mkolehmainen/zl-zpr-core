capnp::generated_code!(pub mod cli_capnp);

pub use cli_capnp as v1;

pub mod data_home;
pub mod socket_owner;
pub mod user_id;

pub use data_home::get_data_home;
#[cfg(unix)]
pub use socket_owner::owner_socket_dir;
pub use socket_owner::{
    SocketOwner, choose_socket_path, control_socket_path, resolve_socket_owner, socket_is_live,
};
pub use user_id::{current_user_id, is_elevated};
