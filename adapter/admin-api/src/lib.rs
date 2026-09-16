capnp::generated_code!(pub mod cli_capnp);

pub use cli_capnp as v1;

pub mod data_home;
pub mod rpc_commands;
pub mod socket_owner;

pub use data_home::get_data_home;
pub use socket_owner::{
    SocketOwner, capture_socket_path, choose_socket_path, control_socket_path, owner_socket_dir,
    resolve_socket_owner, socket_is_live,
};
