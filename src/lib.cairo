pub mod types;
pub mod i_context_configs;

// Export the types and interfaces
pub use types::{
    Application,
    ApplicationId,
    ApplicationBlob,
    Context,
    Capability,
    Signed,
    ContextId,
    RequestKind,
    Request,
    ContextIdentity,
    ContextRequestKind,
    ContextRequest,
    // Add any new traits if needed
    // ContextIdentitySerde,
    // ContextIdentityZero,
    // ContextIdentityFormat,
};
pub use i_context_configs::{
    IContextConfigs, 
    IContextConfigsDispatcher, 
    IContextConfigsDispatcherTrait, 
    IContextConfigsSafeDispatcher, 
    IContextConfigsSafeDispatcherTrait
};

#[starknet::contract]
pub mod ContextConfig {
    use core::poseidon::poseidon_hash_span;
    use core::ecdsa::check_ecdsa_signature;
    use starknet::storage::{
        Map,
        StoragePointerReadAccess,
        StoragePointerWriteAccess,
        Vec,
        MutableVecTrait
    };
    use context_config::types::{
        Application, 
        ApplicationId,
        ApplicationBlob,
        Context,
        Capability, 
        Signed, 
        ContextId, 
        RequestKind,
        MemberIndex,
        Request, 
        ContextIdentity, 
        ContextRequestKind, 
        ContextCreated,
        MemberAdded,
        MemberRemoved,
        CapabilityGranted,
        ApplicationUpdated,
        CapabilityRevoked,
    };

    use starknet::ContractAddress;

    use openzeppelin_access::ownable::OwnableComponent;
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ContextCreated: ContextCreated,
        MemberAdded: MemberAdded,
        ApplicationUpdated: ApplicationUpdated,
        CapabilityGranted: CapabilityGranted,
        CapabilityRevoked: CapabilityRevoked,
        MemberRemoved: MemberRemoved,
        #[flat]
        OwnableEvent: OwnableComponent::Event
    }

    #[storage]
    struct Storage {
        contexts: Map::<felt252, Context>,
        context_ids: Vec<ContextId>,
        privileges: Map::<felt252, bool>,
        context_members: Map::<(felt252, MemberIndex), ContextIdentity>,
        context_members_nonce: Map::<felt252, u64>,
        context_members_keys: Map::<felt252, felt252>,
        context_member_indices: Map::<felt252, MemberIndex>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl InternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl ContextConfigsImpl of super::i_context_configs::IContextConfigs<ContractState> {

        fn application(self: @ContractState, context_id: ContextId) -> Option<Application> {
            let context_key = self.create_context_key(@context_id);
            let context = self.contexts.read(context_key);
            if context.member_count > 0 {
                Option::Some(context.application)
            } else {
                Option::None
            }
        }

        fn get_member_nonce(
            self: @ContractState, 
            context_id: ContextId, 
            member_id: ContextIdentity
        ) -> u64 {
            let nonce_key = self.create_member_key(@context_id, @member_id);
            self.context_members_nonce.read(nonce_key)
        }

        fn has_member(
            self: @ContractState, 
            context_id: ContextId, 
            member_id: ContextIdentity
        ) -> bool {
            let member_key = self.create_member_key(@context_id, @member_id);
            self.context_member_indices.read(member_key) != 0
        }

        fn members(
            self: @ContractState, 
            context_id: ContextId, 
            offset: u32, 
            length: u32
        ) -> Array<ContextIdentity> {
            let context_key = self.create_context_key(@context_id);
            let context = self.contexts.read(context_key);
            let mut members = ArrayTrait::new();
            let total_members = context.member_count;
            let end = min(offset + length, total_members);
            
            let mut i = offset + 1;
            loop {
                if i > end {
                    break;
                }
                let member = self.context_members.read((context_key, i));
                members.append(member);
                i += 1;
            };
            
            members
        }

        fn privileges(
            self: @ContractState, 
            context_id: ContextId, 
            identities: Array<ContextIdentity>
        ) -> Array<(ContextIdentity, Array<Capability>)> {
            let context_key = self.create_context_key(@context_id);
            let mut result = ArrayTrait::new();
            let context = self.contexts.read(context_key);

            if identities.len() == 0 {
                // Return privileges for all members
                let mut i: u32 = 1;
                loop {
                    if i > context.member_count {
                        break;
                    }
                    let member = self.context_members.read((context_key, i));
                    let capabilities = self.get_member_capabilities(context_id.clone(), member);
                    result.append((member, capabilities));
                    i += 1;
                };
            } else {
                // Return privileges for specified members
                let mut i: u32 = 0;
                loop {
                    match identities.get(i) {
                        Option::Some(identity_box) => {
                            let identity = *identity_box.unbox();
                            let capabilities = self.get_member_capabilities(context_id.clone(), identity);
                            result.append((identity, capabilities));
                            i += 1;
                        },
                        Option::None => { break; },
                    }
                };
            };
            
            result
        }

        fn erase(ref self: ContractState) {
            self.ownable.assert_only_owner();
            
            // Erase all contexts
            let context_number = self.context_ids.len();
            for i in 0..context_number {
                let context_id = self.context_ids.at(i).read();
                let context_key = self.create_context_key(@context_id);
                let context = self.contexts.read(context_key);
                let member_count = context.member_count;
                
                // Remove all members from the context
                let mut j: u32 = 1;
                loop {
                    if j > member_count {
                        break;
                    }
                    let member = self.context_members.read((context_key, j));
                    
                    // Clear member storage
                    self.context_members.write(
                        (context_key, j), 
                        ContextIdentity { high: 0, low: 0 }
                    );
                    
                    // Clear member index and nonce
                    let member_key = self.create_member_key(@context_id, @member);
                    self.context_member_indices.write(member_key, 0);
                    self.context_members_nonce.write(member_key, 0);
                    
                    // Revoke all privileges
                    self.revoke_all_privileges(@context_id, member);
                    
                    j += 1;
                };
                
                // Reset context
                self.contexts.write(
                    context_key, 
                    Context {
                        application: Application {
                            id: ApplicationId { high: 0, low: 0 },
                            blob: ApplicationBlob { high: 0, low: 0 },
                            size: 0,
                            source: "",
                            metadata: "",
                        },
                        member_count: 0,
                        application_revision: 0,  // Initial revision
                        members_revision: 0,      // Initial revision
                    }
                );
            }
        }
        
        fn mutate(ref self: ContractState, signed_request: Signed) {
            // Deserialize the payload
            let mut serialized = signed_request.payload.span();
            let request: Request = Serde::deserialize(ref serialized).unwrap();

            // Verify signature
            assert(
                self.verify_signature(signed_request, request.signer_id), 
                'Invalid signature'
            );

            // Add key relation between ecdsa public key and ed25519 public key
            let signer_key = self.create_identity_key(@request.signer_id);
            let user_key = self.create_identity_key(@request.user_id);
            self.context_members_keys.write(signer_key, user_key);

            match request.kind {
                RequestKind::Context(context_request) => {
                    match context_request.kind {  
                        ContextRequestKind::Add((author_id, application)) => {
                            self.add_context(
                                request.user_id, 
                                context_request.context_id, 
                                author_id, 
                                application
                            );
                        },
                        ContextRequestKind::UpdateApplication(application) => {
                            // Verify nonce
                            // let nonce_key = self.create_member_key(
                            //     @context_request.context_id, 
                            //     @request.signer_id
                            // );
                            // let current_nonce = self.context_members_nonce.read(nonce_key);
                            // assert(current_nonce == request.nonce, 'Nonce mismatch');
                            
                            // // Update nonce
                            // self.context_members_nonce.write(nonce_key, current_nonce + 1);
                            
                            // Update application
                            self.update_application(
                                request.user_id,
                                context_request.context_id,
                                application
                            );
                        },
                        ContextRequestKind::AddMembers(members) => {
                            // Verify nonce
                            // let nonce_key = self.create_member_key(
                            //     @context_request.context_id, 
                            //     @request.signer_id
                            // );
                            // let current_nonce = self.context_members_nonce.read(nonce_key);
                            // assert(current_nonce == request.nonce, 'Nonce mismatch');
                            
                            // // Update nonce
                            // self.context_members_nonce.write(nonce_key, current_nonce + 1);
                            
                            // Add members
                            self.add_members(
                                request.user_id,
                                context_request.context_id,
                                members
                            );
                        },
                        ContextRequestKind::RemoveMembers(members) => {
                            // Verify nonce
                            // let nonce_key = self.create_member_key(
                            //     @context_request.context_id, 
                            //     @request.signer_id
                            // );
                            // let current_nonce = self.context_members_nonce.read(nonce_key);
                            // assert(current_nonce == request.nonce, 'Nonce mismatch');
                            
                            // // Update nonce
                            // self.context_members_nonce.write(nonce_key, current_nonce + 1);
                            
                            // Remove members
                            self.remove_members(
                                request.user_id,
                                context_request.context_id,
                                members
                            );
                        },
                        ContextRequestKind::Grant(capabilities) => {
                            // Verify nonce
                            // let nonce_key = self.create_member_key(
                            //     @context_request.context_id, 
                            //     @request.signer_id
                            // );
                            // let current_nonce = self.context_members_nonce.read(nonce_key);
                            // assert(current_nonce == request.nonce, 'Nonce mismatch');
                            
                            // // Update nonce
                            // self.context_members_nonce.write(nonce_key, current_nonce + 1);
                            
                            // Grant capabilities
                            self.grant(
                                request.user_id,
                                context_request.context_id,
                                capabilities
                            );
                        },
                        ContextRequestKind::Revoke(capabilities) => {
                            // Verify nonce
                            // let nonce_key = self.create_member_key(
                            //     @context_request.context_id, 
                            //     @request.signer_id
                            // );
                            // let current_nonce = self.context_members_nonce.read(nonce_key);
                            // assert(current_nonce == request.nonce, 'Nonce mismatch');
                            
                            // // Update nonce
                            // self.context_members_nonce.write(nonce_key, current_nonce + 1);
                            
                            // Revoke capabilities
                            self.revoke(
                                request.user_id,
                                context_request.context_id,
                                capabilities
                            );
                        },
                    }
                }
            }
        }

        fn application_revision(self: @ContractState, context_id: ContextId) -> u64 {
            let context_key = self.create_context_key(@context_id);
            let context = self.contexts.read(context_key);
            context.application_revision
        }

        fn members_revision(self: @ContractState, context_id: ContextId) -> u64 {
            let context_key = self.create_context_key(@context_id);
            let context = self.contexts.read(context_key);
            context.members_revision
        }
    }

    fn min(a: u32, b: u32) -> u32 {
        if a < b { a } else { b }
    }

    #[generate_trait]
    impl SignatureVerifier of SignatureVerifierTrait {
        fn verify_signature(self: @ContractState, signed_request: Signed, signer_id: ContextIdentity) -> bool {
            let mut serialized = signed_request.payload.span();
            let message_hash = poseidon_hash_span(serialized);

            // Reconstruct the 32-byte public key from high and low parts
            // Each part is 16 bytes, so we need to shift high by 16 bytes (128 bits)
            let full_public_key = signer_id.high * 0x100000000000000000000000000000000 + signer_id.low;

            check_ecdsa_signature(
                message_hash, 
                full_public_key, 
                signed_request.signature_r, 
                signed_request.signature_s
            )
        }
    }

    #[generate_trait]
    impl ContextHelpers of ContextHelpersTrait {
        fn add_context(
            ref self: ContractState,
            signer_id: ContextIdentity,
            context_id: ContextId,
            author_id: ContextIdentity,
            application: Application
        ) {
            // Check if context already exists
            let context_key = self.create_context_key(@context_id);
            let existing_context = self.contexts.read(context_key);
            assert(existing_context.member_count == 0, 'Context already exists');
        
            // Create new context with initial revisions
            let new_context = Context {
                application: application,
                member_count: 0,
                application_revision: 1,  // Initial revision
                members_revision: 1,      // Initial revision
            };
            self.contexts.write(context_key, new_context);
            self.context_ids.append().write(context_id.clone());

            // Add author as first member
            self.add_member(context_id.clone(), author_id);
        
            // Grant initial privileges to author
            self.grant_privilege(@context_id, author_id, Capability::ManageApplication);
            
            // Update nonce for author
            let nonce_key = self.create_member_key(@context_id, @author_id);
            self.context_members_nonce.write(nonce_key, 1);
            
            // Grant member management privilege
            self.grant_privilege(@context_id, author_id, Capability::ManageMembers);
        
            // Log context creation
            self.emit(ContextCreated { 
                message: format!(
                    "Context {} created with author ({}, {})", 
                    context_id, author_id.high, author_id.low
                ) 
            });
        }

        fn add_member(
            ref self: ContractState,
            context_id: ContextId,
            member_id: ContextIdentity
        ) {
            let context_key = self.create_context_key(@context_id);
            // Read the current context
            let mut context = self.contexts.read(context_key);
            
            // Create storage key for member index
            let member_key = self.create_member_key(@context_id, @member_id);
            
            // Check if the member already exists
            let existing_index = self.context_member_indices.read(member_key);
            assert(existing_index == 0, 'Member already exists');

            // Add the new member
            let new_index = context.member_count + 1;
            self.context_members.write((context_key, new_index), member_id);
            self.context_member_indices.write(member_key, new_index);

            // Update the member count
            context.member_count += 1;
            self.contexts.write(context_key, context);

            // Emit an event
            self.emit(MemberAdded { 
                message: format!(
                    "Added member ({}, {}) to context ({}, {})", 
                    member_id.high, member_id.low,
                    context_id.high, context_id.low
                ) 
            });
        }

        fn update_application(
            ref self: ContractState,
            signer_id: ContextIdentity,
            context_id: ContextId,
            new_application: Application
        ) {
            let context_key = self.create_context_key(@context_id);
            let mut context = self.contexts.read(context_key);
            assert(context.member_count > 0, 'Context does not exist');

            // Check if the signer has the necessary permissions
            assert(
                self.has_privilege(@context_id, signer_id, Capability::ManageApplication), 
                'Unauthorized'
            );

            // Store old application for event
            let old_application = context.application;

            // Increment application revision
            context.application_revision += 1;
            // Update the application
            context.application = new_application.clone();
            // Save the updated context
            self.contexts.write(context_key, context);

            // Emit event
            self.emit(ApplicationUpdated { 
                message: format!(
                    "Updated application for context ({}, {}) from ({}, {}) to ({}, {})", 
                    context_id.high, context_id.low,
                    old_application.id.high, old_application.id.low,
                    new_application.id.high, new_application.id.low
                ) 
            });
        }

        fn add_members(
            ref self: ContractState,
            signer_id: ContextIdentity,
            context_id: ContextId,
            members: Array<ContextIdentity>
        ) {
            let context_key = self.create_context_key(@context_id);
            let mut context = self.contexts.read(context_key);
            assert(context.member_count > 0, 'Context does not exist');

            // Check if the signer has the necessary permissions
            assert(
                self.has_privilege(@context_id, signer_id, Capability::ManageMembers), 
                'Unauthorized'
            );

            // Add members
            let mut i: u32 = 0;
            loop {
                match members.get(i) {
                    Option::Some(member_box) => {
                        let member = *member_box.unbox();
                        let member_key = self.create_member_key(@context_id, @member);
                        
                        // Check if the member already exists
                        assert(
                            self.context_member_indices.read(member_key) == 0, 
                            'Member already exists'
                        );

                        // Add the member
                        context.member_count += 1;
                        self.context_members.write((context_key, context.member_count), member);
                        self.context_member_indices.write(member_key, context.member_count);
                        
                        // Initialize nonce
                        self.context_members_nonce.write(member_key, 0);

                        // Emit event
                        self.emit(MemberAdded { 
                            message: format!(
                                "Added member ({}, {}) to context ({}, {})", 
                                member.high, member.low,
                                context_id.high, context_id.low
                            ) 
                        });

                        i += 1;
                    },
                    Option::None => { break; },
                }
            };

            // Increment members revision at the end
            context.members_revision += 1;
            // Save the updated context
            self.contexts.write(context_key, context);
        }

        fn remove_members(
            ref self: ContractState,
            signer_id: ContextIdentity,
            context_id: ContextId,
            members: Array<ContextIdentity>
        ) {
            let context_key = self.create_context_key(@context_id);
            let mut context = self.contexts.read(context_key);
            assert(context.member_count > 0, 'Context does not exist');

            // Check if the signer has the necessary permissions
            assert(
                self.has_privilege(@context_id, signer_id, Capability::ManageMembers), 
                'Unauthorized'
            );

            // Remove members
            let mut i: u32 = 0;
            loop {
                match members.get(i) {
                    Option::Some(member_box) => {
                        let member = *member_box.unbox();
                        let member_key = self.create_member_key(@context_id, @member);
                        
                        // Check if the member exists
                        let member_index = self.context_member_indices.read(member_key);
                        if member_index != 0 {
                            // Move the last member to this position
                            if member_index != context.member_count {
                                let last_member = self.context_members.read((context_key, context.member_count));
                                self.context_members.write((context_key, member_index), last_member);
                                // Create storage key for last member
                                let last_member_key = self.create_member_key(@context_id, @last_member);
                                self.context_member_indices.write(last_member_key, member_index);
                            }
                            
                            // Remove the member
                            self.context_members.write(
                                (context_key, context.member_count), 
                                ContextIdentity { high: 0, low: 0 }
                            );
                            self.context_member_indices.write(member_key, 0);
                            
                            // Decrease the member count
                            context.member_count -= 1;
                            
                            // Revoke all privileges for this member in this context
                            self.revoke_all_privileges(@context_id, member);
                            
                            // Emit an event for the removed member
                            self.emit(MemberRemoved { 
                                message: format!("Removed member ({}, {}) from context ({}, {})", 
                                    member.high, member.low,
                                    context_id.high, context_id.low
                                ) 
                            });
                        }
                        i += 1;
                    },
                    Option::None => { break; },
                }
            };

            // Increment members revision at the end
            context.members_revision += 1;

            // Update the context with the new member count
            self.contexts.write(context_key, context);
        }

        fn grant(
            ref self: ContractState,
            signer_id: ContextIdentity,
            context_id: ContextId,
            capabilities: Array<(ContextIdentity, Capability)>
        ) {
            let context_key = self.create_context_key(@context_id);
            let context = self.contexts.read(context_key);
            assert(context.member_count > 0, 'Context does not exist');

            // Check if the signer has the necessary permissions
            assert(
                self.has_privilege(@context_id, signer_id, Capability::ManageMembers), 
                'Unauthorized'
            );

            // Grant capabilities
            let mut i: u32 = 0;
            loop {
                match capabilities.get(i) {
                    Option::Some(capability_box) => {
                        let (identity, capability) = *capability_box.unbox();
                        let member_key = self.create_member_key(@context_id, @identity);
                        
                        // Check if the identity is a member of the context
                        let member_index = self.context_member_indices.read(member_key);
                        assert(member_index != 0, 'Not a member of the context');

                        // Grant the capability
                        self.grant_privilege(@context_id, identity, capability);
                        
                        // Update nonce
                        // let nonce_key = self.create_member_key(@context_id, @identity);
                        // self.context_members_nonce.write(nonce_key, 1);

                        i += 1;
                    },
                    Option::None => { break; },
                }
            };
        }

        fn revoke(
            ref self: ContractState,
            signer_id: ContextIdentity,
            context_id: ContextId,
            capabilities: Array<(ContextIdentity, Capability)>
        ) {
            let context_key = self.create_context_key(@context_id);
            let context = self.contexts.read(context_key);
            assert(context.member_count > 0, 'Context does not exist');

            assert(
                self.has_privilege(@context_id, signer_id, Capability::ManageMembers), 
                'Unauthorized'
            );

            let mut i: u32 = 0;
            loop {
                match capabilities.get(i) {
                    Option::Some(capability_box) => {
                        let (identity, capability) = *capability_box.unbox();
                        self.revoke_privilege(@context_id, identity, capability);
                        i += 1;
                    },
                    Option::None => { break; },
                }
            };
        }
    }

    #[generate_trait]
    impl PrivilegeHelpers of PrivilegeHelpersTrait {
        fn create_privilege_key(
            self: @ContractState,
            context_id: @ContextId,
            member_id: @ContextIdentity,
            capability: Capability
        ) -> felt252 {
            let context_key = self.create_context_key(context_id);
            let member_key = self.create_identity_key(member_id);
            let capability_felt: felt252 = capability.into();
            poseidon_hash_span(array![context_key, member_key, capability_felt].span())
        }

        fn has_privilege(
            self: @ContractState,
            context_id: @ContextId,
            member_id: ContextIdentity,
            capability: Capability
        ) -> bool {
            let privilege_key = self.create_privilege_key(context_id, @member_id, capability);
            self.privileges.read(privilege_key)
        }

        fn get_member_capabilities(
            self: @ContractState, 
            context_id: ContextId, 
            member: ContextIdentity
        ) -> Array<Capability> {
            let mut capabilities = ArrayTrait::new();
            if self.has_privilege(@context_id, member, Capability::ManageApplication) {
                capabilities.append(Capability::ManageApplication);
            }
            if self.has_privilege(@context_id, member, Capability::ManageMembers) {
                capabilities.append(Capability::ManageMembers);
            }
            capabilities
        }

        fn grant_privilege(
            ref self: ContractState,
            context_id: @ContextId,
            member_id: ContextIdentity,
            capability: Capability
        ) {
            let privilege_key = self.create_privilege_key(context_id, @member_id, capability);
            self.privileges.write(privilege_key, true);

            // Increment members_revision since member capabilities changed
            let context_key = self.create_context_key(context_id);
            let mut context = self.contexts.read(context_key);
            context.members_revision += 1;
            self.contexts.write(context_key, context);

            self.emit(CapabilityGranted { 
                message: format!(
                    "Granted {} to member ({}, {}) in context ({}, {})", 
                    capability, 
                    member_id.high, member_id.low,
                    context_id.high, context_id.low
                ) 
            });
        }

        fn revoke_privilege(
            ref self: ContractState,
            context_id: @ContextId,
            member_id: ContextIdentity,
            capability: Capability
        ) {
            let privilege_key = self.create_privilege_key(context_id, @member_id, capability);
            self.privileges.write(privilege_key, false);

            // Increment members_revision since member capabilities changed
            let context_key = self.create_context_key(context_id);
            let mut context = self.contexts.read(context_key);
            context.members_revision += 1;
            self.contexts.write(context_key, context);

            self.emit(CapabilityRevoked { 
                message: format!(
                    "Revoked {} from member ({}, {}) in context ({}, {})", 
                    capability, 
                    member_id.high, member_id.low,
                    context_id.high, context_id.low
                ) 
            });
        }

        fn revoke_all_privileges(
            ref self: ContractState,
            context_id: @ContextId,
            member_id: ContextIdentity
        ) {
            // Since we're calling revoke_privilege twice, we only need one revision increment
            let context_key = self.create_context_key(context_id);
            let mut context = self.contexts.read(context_key);
            context.members_revision += 1;
            self.contexts.write(context_key, context);

            // Now revoke the privileges
            self.revoke_privilege(context_id, member_id, Capability::ManageMembers);
            self.revoke_privilege(context_id, member_id, Capability::ManageApplication);
        }
    }

    #[generate_trait]
    impl StorageHelpers of StorageHelpersTrait {
        // Helper to create storage key from context_id
        fn create_context_key(self: @ContractState, context_id: @ContextId) -> felt252 {
            poseidon_hash_span(array![*context_id.high, *context_id.low].span())
        }

        // Helper to create storage key from context_id and identity
        fn create_member_key(
            self: @ContractState, 
            context_id: @ContextId, 
            identity: @ContextIdentity
        ) -> felt252 {
            let context_key = self.create_context_key(context_id);
            let identity_key = self.create_identity_key(identity);
            poseidon_hash_span(array![context_key, identity_key].span())
        }

        // Helper to create storage key from identity
        fn create_identity_key(self: @ContractState, identity: @ContextIdentity) -> felt252 {
            poseidon_hash_span(array![*identity.high, *identity.low].span())
        }
    }
}
