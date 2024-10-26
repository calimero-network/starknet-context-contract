
use core::fmt::{Display, Error, Formatter};

#[derive(Drop, Serde, starknet::Store)]
pub type ContextId = felt252;

#[derive(Drop, Serde, starknet::Store)]
pub type MemberIndex = u32;

// Context Member ID
#[derive(Drop, Serde, Debug, starknet::Store)]
pub type ContextIdentity = felt252;

// Context
#[derive(Drop, Serde, starknet::Store)]
pub struct Context {
    pub application: Application,
    pub member_count: u32,
}

// Context Application
#[derive(Drop, Serde, Debug, Clone, starknet::Store)]
pub struct Application {
    pub id: felt252,  // Represents [u8; 32]
    pub blob: felt252,  // Represents [u8; 32]
    pub size: u64,
    pub source: ByteArray,  // Represents ApplicationSource
    pub metadata: ByteArray,  // Represents ApplicationMetadata
}

// Context Capabilities
#[derive(Drop, Serde, PartialEq, Copy, Debug)]
pub enum Capability {
    ManageApplication,
    ManageMembers,
}

// Add this implementation to your types.cairo file
impl CapabilityDisplay of core::fmt::Display<Capability> {
    fn fmt(self: @Capability, ref f: Formatter) -> Result<(), Error> {
        let capability_str: ByteArray = match self {
            Capability::ManageApplication => "ManageApplication",
            Capability::ManageMembers => "ManageMembers",
        };
        Display::fmt(@capability_str, ref f)
    }
}

// Convert Capability to felt252
impl CapabilityIntoFelt252 of Into<Capability, felt252> {
    fn into(self: Capability) -> felt252 {
        match self {
            Capability::ManageApplication => 0,
            Capability::ManageMembers => 1,
        }
    }
}

// Convert felt252 to Capability
impl Felt252TryIntoCapability of TryInto<felt252, Capability> {
    fn try_into(self: felt252) -> Option<Capability> {
        match self {
            0 => Option::Some(Capability::ManageApplication),
            1 => Option::Some(Capability::ManageMembers),
            _ => Option::None,
        }
    }
}

#[derive(Drop, Serde, Debug)]
pub struct Signed {
    pub payload: Array<felt252>,
    pub signature_r: felt252,
    pub signature_s: felt252,
}

#[derive(Drop, Serde, Debug)]
pub struct Request {
    pub kind: RequestKind,
    pub signer_id: ContextIdentity,
    pub nonce: u64,
}

#[derive(Drop, Serde, Debug)]
pub enum RequestKind {
    Context: ContextRequest,
}

#[derive(Drop, Serde, Debug)]
pub struct ContextRequest {
    pub context_id: ContextId,
    pub kind: ContextRequestKind,
}

#[derive(Drop, Serde, Debug)]
pub enum ContextRequestKind {
    Add: (ContextIdentity, Application),
    UpdateApplication: Application,
    AddMembers: Array<ContextIdentity>,
    RemoveMembers: Array<ContextIdentity>,
    Grant: Array<(ContextIdentity, Capability)>,
    Revoke: Array<(ContextIdentity, Capability)>,
}

// Events
#[derive(Drop, starknet::Event)]
pub struct ContextCreated {
    pub message: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct MemberRemoved {
    pub message: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct MemberAdded {
    pub message: ByteArray,
}

// #[event]
#[derive(Drop, starknet::Event)]
pub struct ApplicationUpdated {
    pub message: ByteArray,
}


#[derive(Drop, starknet::Event)]
pub struct CapabilityGranted {
    pub message: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct CapabilityRevoked {
    pub message: ByteArray,
}
