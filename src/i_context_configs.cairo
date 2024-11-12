use super::types::{
    Signed,
    ContextId, 
    Application, 
    ContextIdentity, 
    Capability, 
};

#[starknet::interface]
pub trait IContextConfigs<TContractState> {
    // Query functions
    fn application(self: @TContractState, context_id: ContextId) -> Option<Application>;
    fn members(self: @TContractState, context_id: ContextId, offset: u32, length: u32) -> Array<ContextIdentity>;
    fn privileges(self: @TContractState, context_id: ContextId, identities: Array<ContextIdentity>) -> Array<(ContextIdentity, Array<Capability>)>;
    fn get_member_nonce(self: @TContractState, context_id: ContextId, member_id: ContextIdentity) -> u64;
    fn has_member(self: @TContractState, context_id: ContextId, member_id: ContextIdentity) -> bool;
    fn application_revision(self: @TContractState, context_id: ContextId) -> u64;
    fn members_revision(self: @TContractState, context_id: ContextId) -> u64;
    
    // Mutation functions
    fn mutate(ref self: TContractState, signed_request: Signed);
    fn erase(ref self: TContractState);
}