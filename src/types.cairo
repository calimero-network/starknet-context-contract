use core::fmt::{Display, Error, Formatter};
use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

#[derive(Drop, Serde, Copy, Debug, starknet::Store)]
pub struct ContextId {
    pub high: felt252,  // First 16 bytes (128 bits)
    pub low: felt252,   // Second 16 bytes (128 bits)
}

// Add equality comparison
impl ContextIdPartialEq of PartialEq<ContextId> {
    fn eq(lhs: @ContextId, rhs: @ContextId) -> bool {
        lhs.high == rhs.high && lhs.low == rhs.low
    }

    fn ne(lhs: @ContextId, rhs: @ContextId) -> bool {
        !(lhs.high == rhs.high && lhs.low == rhs.low)
    }
}

// Add conversion to felt252 for storage keys
impl ContextIdIntoFelt252 of Into<ContextId, felt252> {
    fn into(self: ContextId) -> felt252 {
        poseidon_hash_span(array![self.high, self.low].span())
    }
}

// Add Display implementation for better error messages and events
impl ContextIdDisplay of Display<ContextId> {
    fn fmt(self: @ContextId, ref f: Formatter) -> Result<(), Error> {
        write!(f, "({}, {})", self.high, self.low)
    }
}

#[derive(Drop, Serde, starknet::Store)]
pub type MemberIndex = u32;

// Context Member ID
#[derive(Drop, Serde, Debug, Copy, starknet::Store)]
pub struct ContextIdentity {
    pub high: felt252,  // First 16 bytes (128 bits)
    pub low: felt252,   // Second 16 bytes (128 bits)
}

// Add equality comparison
impl ContextIdentityPartialEq of PartialEq<ContextIdentity> {
    fn eq(lhs: @ContextIdentity, rhs: @ContextIdentity) -> bool {
        lhs.high == rhs.high && lhs.low == rhs.low
    }

    fn ne(lhs: @ContextIdentity, rhs: @ContextIdentity) -> bool {
        !(lhs.high == rhs.high && lhs.low == rhs.low)
    }
}

// Add conversion to felt252 for storage keys
impl ContextIdentityIntoFelt252 of Into<ContextIdentity, felt252> {
    fn into(self: ContextIdentity) -> felt252 {
        poseidon_hash_span(array![self.high, self.low].span())
    }
}

// Add Display implementation for better error messages and events
impl ContextIdentityDisplay of Display<ContextIdentity> {
    fn fmt(self: @ContextIdentity, ref f: Formatter) -> Result<(), Error> {
        write!(f, "({}, {})", self.high, self.low)
    }
}

// Context
#[derive(Drop, Serde, starknet::Store)]
pub struct Context {
    pub application: Application,
    pub member_count: u32,
    pub application_revision: u64,  // Track application changes
    pub members_revision: u64,      // Track member list changes
    pub proxy_address: ContractAddress,
}

// Application ID (32 bytes)
#[derive(Drop, Serde, Debug, Clone, starknet::Store)]
pub struct ApplicationId {
    pub high: felt252,  // First 16 bytes
    pub low: felt252,   // Second 16 bytes
}

impl ApplicationIdPartialEq of PartialEq<ApplicationId> {
    fn eq(lhs: @ApplicationId, rhs: @ApplicationId) -> bool {
        lhs.high == rhs.high && lhs.low == rhs.low
    }
    fn ne(lhs: @ApplicationId, rhs: @ApplicationId) -> bool {
        !(lhs.high == rhs.high && lhs.low == rhs.low)
    }
}

impl ApplicationIdIntoFelt252 of Into<ApplicationId, felt252> {
    fn into(self: ApplicationId) -> felt252 {
        poseidon_hash_span(array![self.high, self.low].span())
    }
}

impl ApplicationIdDisplay of Display<ApplicationId> {
    fn fmt(self: @ApplicationId, ref f: Formatter) -> Result<(), Error> {
        write!(f, "({}, {})", self.high, self.low)
    }
}

// Application Blob (32 bytes)
#[derive(Drop, Serde, Debug, Clone, starknet::Store)]
pub struct ApplicationBlob {
    pub high: felt252,  // First 16 bytes
    pub low: felt252,   // Second 16 bytes
}

impl ApplicationBlobPartialEq of PartialEq<ApplicationBlob> {
    fn eq(lhs: @ApplicationBlob, rhs: @ApplicationBlob) -> bool {
        lhs.high == rhs.high && lhs.low == rhs.low
    }
    fn ne(lhs: @ApplicationBlob, rhs: @ApplicationBlob) -> bool {
        !(lhs.high == rhs.high && lhs.low == rhs.low)
    }
}

impl ApplicationBlobIntoFelt252 of Into<ApplicationBlob, felt252> {
    fn into(self: ApplicationBlob) -> felt252 {
        poseidon_hash_span(array![self.high, self.low].span())
    }
}

impl ApplicationBlobDisplay of Display<ApplicationBlob> {
    fn fmt(self: @ApplicationBlob, ref f: Formatter) -> Result<(), Error> {
        write!(f, "({}, {})", self.high, self.low)
    }
}

// Updated Application struct
#[derive(Drop, Serde, Debug, Clone, starknet::Store)]
pub struct Application {
    pub id: ApplicationId,
    pub blob: ApplicationBlob,
    pub size: u64,
    pub source: ByteArray,
    pub metadata: ByteArray,
}

// You might also want to add a Display implementation for Application
impl ApplicationDisplay of Display<Application> {
    fn fmt(self: @Application, ref f: Formatter) -> Result<(), Error> {
        write!(
            f, 
            "Application {{ id: {}, blob: {}, size: {}, source: {}, metadata: {} }}", 
            self.id, self.blob, self.size, self.source, self.metadata
        )
    }
}

// Context Capabilities
#[derive(Drop, Serde, PartialEq, Copy, Debug)]
pub enum Capability {
    ManageApplication,
    ManageMembers,
    ProxyCode,
}

// Add this implementation to your types.cairo file
impl CapabilityDisplay of core::fmt::Display<Capability> {
    fn fmt(self: @Capability, ref f: Formatter) -> Result<(), Error> {
        let capability_str: ByteArray = match self {
            Capability::ManageApplication => "ManageApplication",
            Capability::ManageMembers => "ManageMembers",
            Capability::ProxyCode => "ProxyCode",
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
            Capability::ProxyCode => 2,
        }
    }
}

// Convert felt252 to Capability
impl Felt252TryIntoCapability of TryInto<felt252, Capability> {
    fn try_into(self: felt252) -> Option<Capability> {
        match self {
            0 => Option::Some(Capability::ManageApplication),
            1 => Option::Some(Capability::ManageMembers),
            2 => Option::Some(Capability::ProxyCode),
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
    pub user_id: ContextIdentity,
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
    UpgradeProxy: (ContextId, ContextIdentity),
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

#[derive(Drop, starknet::Event)]
pub struct ProxyContractUpgraded {
    pub message: ByteArray,
}

// // Add helper trait for ContextIdentity serialization
// impl ContextIdentitySerde of Serde<ContextIdentity> {
//     fn serialize(self: @ContextIdentity, ref output: Array<felt252>) {
//         self.high.serialize(ref output);
//         self.low.serialize(ref output);
//     }

//     fn deserialize(ref serialized: Span<felt252>) -> Option<ContextIdentity> {
//         Option::Some(ContextIdentity {
//             high: Serde::deserialize(ref serialized)?,
//             low: Serde::deserialize(ref serialized)?,
//         })
//     }
// }

// // Add helper trait for zero value
// impl ContextIdentityZero of Default<ContextIdentity> {
//     fn default() -> ContextIdentity {
//         ContextIdentity { high: 0, low: 0 }
//     }
// }

// // Update event messages to handle new ContextIdentity format
// impl ContextIdentityFormat of core::fmt::Display<ContextIdentity> {
//     fn fmt(self: @ContextIdentity, ref f: Formatter) -> Result<(), Error> {
//         write!(f, "({:#x}, {:#x})", self.high, self.low)  // Hex format for better readability
//     }
// }


