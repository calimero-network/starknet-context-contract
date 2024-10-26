#[cfg(test)]
mod tests {
    use starknet::{
        ContractAddress, 
    };
    use snforge_std::{
        declare, ContractClassTrait, DeclareResultTrait, 
        start_cheat_caller_address, stop_cheat_caller_address, EventSpyAssertionsTrait, spy_events,
    };
    use context_config::{
        Application,
        Signed,
        RequestKind,
        Request, ContextRequestKind, ContextRequest,
        IContextConfigsDispatcher, IContextConfigsDispatcherTrait, IContextConfigsSafeDispatcherTrait, IContextConfigsSafeDispatcher,
    };
    use context_config::ContextConfig::Event;
    use context_config::types::{
        ContextCreated, 
        MemberAdded, 
        Capability, 
        CapabilityGranted, 
        ApplicationUpdated, 
        MemberRemoved,
    };
    use core::traits::Into;
    use core::array::ArrayTrait;
    use core::clone::Clone;
    use core::byte_array::ByteArray;

    use snforge_std::signature::KeyPairTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl};

    use core::poseidon::PoseidonTrait;
    use core::poseidon::poseidon_hash_span;
    use core::hash::{HashStateTrait, HashStateExTrait};

    fn deploy_contract(name: ByteArray) -> (ContractAddress, ContractAddress) {
        let owner: ContractAddress = starknet::contract_address_const::<0x123456789>();

        let mut constructor_calldata = ArrayTrait::new();
        constructor_calldata.append(owner.into());
    
        let contract = declare(name).unwrap().contract_class();
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
    
        (contract_address, owner)
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn test_add_context() {
        // Deploy the contract
        let (contract_address, owner) = deploy_contract("ContextConfig");

        let node1 = KeyPairTrait::<felt252, felt252>::generate();
        let node1_public_key = node1.public_key;
        let node1_id: ContractAddress = node1_public_key.try_into().unwrap();

        let node2 = KeyPairTrait::<felt252, felt252>::generate();
        let node2_public_key = node2.public_key;
        let node2_id: ContractAddress = node2_public_key.try_into().unwrap();

        // Create a dispatcher
        let safe_dispatcher = IContextConfigsSafeDispatcher { contract_address };
        let spy_dispatcher = IContextConfigsDispatcher { contract_address };
        let mut spy = spy_events();

        let alice_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let alice_public_key = alice_key_pair.public_key;
        let alice_id = alice_public_key;
        let mut alice_nonce = 0;

        let bob_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let bob_public_key = bob_key_pair.public_key;
        let bob_id = bob_public_key;
        let mut bob_nonce = 0;

        let carol_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let carol_public_key = carol_key_pair.public_key;
        let carol_id = carol_public_key;

        let context_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let context_public_key = context_key_pair.public_key;
        let context_id = context_public_key;
        
        // Create a signed request
        let mut request = Request {
            signer_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Add((
                        context_id,
                        Application {
                            id: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
                            blob: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
                            size: 0,
                            source: "https://calimero.network",
                            metadata: "Some metadata",
                        }
                    ))
                }
            )
        };
        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
        
        // Call as node1 relayer
        start_cheat_caller_address(contract_address, node1_id);
        // Call the mutate function
        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Entrypoint did not panic"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'signer_id equals context_id', *panic_data.at(0));
            }
        };

        // Create a signed request
        let mut request = Request {
            signer_id: context_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Add((
                        alice_id, 
                        Application {
                            id: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
                            blob: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
                            size: 0,
                            source: "https://calimero.network",
                            metadata: "Some metadata",
                        }
                    ))
                }
            )
        };
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let (r, s): (felt252, felt252) = context_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        // Call the mutate function
        let _res = spy_dispatcher.mutate(signed_request);

        // Assert that the context was created
        spy.assert_emitted(
            @array![
                (
                    contract_address,
                    Event::MemberAdded(
                        MemberAdded { message: format!("Added `{}` as a member of `{}`", alice_id, context_id) }
                    )
                ),
                (
                    contract_address,
                    Event::CapabilityGranted(
                        CapabilityGranted { message: format!("Granted `ManageMembers` to `{}` in `{}`", alice_id, context_id) }
                    )
                ),
                (
                    contract_address,
                    Event::CapabilityGranted(
                        CapabilityGranted { message: format!("Granted `ManageApplication` to `{}` in `{}`", alice_id, context_id) }
                    )
                ),
                (
                    contract_address,
                    Event::ContextCreated(
                        ContextCreated { message: format!("Context {} added", context_id) }
                    )
                )
            ]
        );

        // Stop calling as node1 relayer
        stop_cheat_caller_address(contract_address);
        ///End of successful create_context request///
        
        // Start calling as node2 relayer
        start_cheat_caller_address(contract_address, node2_id);

        // Create a signed request
        let mut request = Request {
            signer_id: context_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Add((
                        alice_id, 
                        Application {
                            id: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
                            blob: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
                            size: 0,
                            source: "https://calimero.network",
                            metadata: "Some metadata",
                        }
                    ))
                }
            )
        };

        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        println!("serialized: {:?}", serialized);

        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = context_key_pair.sign(hash).unwrap();

        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        let mut serialized_signed_request = ArrayTrait::new();
        signed_request.serialize(ref serialized_signed_request);
        println!("serialized_signed_request: {:?}", serialized_signed_request);

        // Call the mutate function
        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Entrypoint did not panic"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'Context already exists', *panic_data.at(0));
            }
        };

        stop_cheat_caller_address(contract_address);

        let application = Application {
            id: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
            blob: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
            size: 0,
            source: "https://calimero.network",
            metadata: "Some metadata",
        };
            
        // Store the application values for later comparison
        let app_id = application.id;
        let app_blob = application.blob;
        let app_size = application.size;
        let app_source = application.source.clone();
        let app_metadata = application.metadata.clone();

        // Verify that the context was added correctly
        match safe_dispatcher.application(context_id.clone()) {
            Result::Ok(result_application) => {
                assert(result_application.id == app_id, 'Incorrect application ID');
                assert(result_application.blob == app_blob, 'Incorrect application blob');
                assert(result_application.size == app_size, 'Incorrect application size');
                assert(result_application.source == app_source, 'Incorrect application source');
                assert(result_application.metadata == app_metadata, 'Incorrect application metadata');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve application: {:?}", error);
            }
        }

        match safe_dispatcher.privileges(context_id.clone(), array![]) {
            Result::Ok(privileges) => {
                let (identity, capabilities) = privileges.at(0);
                assert!(capabilities.len() > 1, "Expected capabilities for the author");
                assert!(identity == @alice_id, "Author ID does not match expected identity");
                // Check specific capabilities
                let expected_capabilities = array![Capability::ManageApplication, Capability::ManageMembers];
                for expected_capability in expected_capabilities {
                    let mut found = false;
                    for k in 0..capabilities.len() {
                        if capabilities.at(k) == @expected_capability {
                            found = true;
                            break;
                        }
                    };
                    assert!(found, "Expected capability not found: {:?}", expected_capability);
                }
            },
            Result::Err(error) => {
                panic!("Failed to retrieve privileges: {:?}", error);
            }
        }

        ///Start of members verification///
        // Verify that the author is a member of the context
        match safe_dispatcher.members(context_id, 0, 10) {
            Result::Ok(members) => {
                assert(members.len() == 1, 'Incorrect number of members');
                assert(*members.at(0) == alice_id, 'Incorrect author ID');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve members: {:?}", error);
            }
        }
        
        start_cheat_caller_address(contract_address, node1_id);

        // Create a signed request
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::AddMembers(array![bob_id.clone()])
                }
            )
        };

        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
        // Call the mutate function
        let _res = spy_dispatcher.mutate(signed_request);

        spy.assert_emitted(
            @array![
                (
                    contract_address,
                    Event::MemberAdded(
                        MemberAdded { message: format!("Added `{}` as a member of `{}`", bob_id, context_id) }
                    )
                ),
            ]
        );

        stop_cheat_caller_address(contract_address);

        // Verify that the members were added correctly
        match safe_dispatcher.members(context_id, 0, 10) {
            Result::Ok(members) => {
                assert(members.len() == 2, 'Incorrect number of members');
                assert(*members.at(0) == alice_id, 'Incorrect author ID');
                assert(*members.at(1) == bob_id, 'Incorrect bob ID');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve members: {:?}", error);
            }
        }

        match safe_dispatcher.privileges(context_id, array![bob_id.clone()]) {
            Result::Ok(privileges) => {
                let (identity, capabilities) = privileges.at(0);
                assert!(identity == @bob_id, "Identity does not match expected identity");
                assert!(capabilities.len() == 0, "Expected no capabilities for bob");
            },
            Result::Err(error) => {
                panic!("Failed to retrieve privileges: {:?}", error);
            }
        }

        start_cheat_caller_address(contract_address, node1_id);

        // Create a signed request
        let mut request = Request {
            signer_id: bob_id.clone(),
            nonce: bob_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::AddMembers(array![carol_id])
                }
            )
        };
        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = bob_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Entrypoint did not panic"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'unable to update member list', *panic_data.at(0));
            }
        };

        // Create a signed request
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Grant(array![(bob_id.clone(), Capability::ManageMembers)])
                }
            )
        };
        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();

        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        let _res = spy_dispatcher.mutate(signed_request);

        spy.assert_emitted(
            @array![
                (
                    contract_address,
                    Event::CapabilityGranted(CapabilityGranted { message: format!("Granted `ManageMembers` to `{}` in `{}`", bob_id.clone(), context_id.clone()) })
                ),
            ]
        );

        // Create a signed request
        bob_nonce += 1;
        let mut request = Request {
            signer_id: bob_id.clone(),
            nonce: bob_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::AddMembers(array![carol_id])
                }
            )
        };

        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);

        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = bob_key_pair.sign(hash).unwrap();

        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        let _res = spy_dispatcher.mutate(signed_request);

        spy.assert_emitted(
            @array![
                (
                    contract_address,
                    Event::MemberAdded(MemberAdded { message: format!("Added `{}` as a member of `{}`", carol_id, context_id) })
                ),
            ]
        );

        // Verify that the members were added correctly
        match safe_dispatcher.members(context_id, 0, 10) {
            Result::Ok(members) => {
                assert(members.len() == 3, 'Incorrect number of members');
                assert(*members.at(0) == alice_id, 'Incorrect alice ID');
                assert(*members.at(1) == bob_id, 'Incorrect bob ID');
                assert(*members.at(2) == carol_id, 'Incorrect carol ID');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve members: {:?}", error);
            }
        }

        match safe_dispatcher.privileges(context_id, array![]) {
            Result::Ok(privileges) => {
                for i in 0..privileges.len() {
                    let (identity, capabilities) = privileges.at(i);
                    if identity == @alice_id {
                        assert!(capabilities.len() == 2, "Expected 2 capabilities for alice");
                        let expected_capabilities = array![Capability::ManageApplication, Capability::ManageMembers];
                        for expected_capability in expected_capabilities {
                            let mut found = false;
                            for k in 0..capabilities.len() {
                                if capabilities.at(k) == @expected_capability {
                                    found = true;
                                    break;
                                }
                            };
                            assert!(found, "Expected capability not found: {:?}", expected_capability);
                        }
                    } else if identity == @bob_id {
                        assert!(capabilities.len() == 1, "Expected 1 capability for bob");  
                        let expected_capabilities = array![Capability::ManageMembers];
                        for expected_capability in expected_capabilities {
                            let mut found = false;
                            for k in 0..capabilities.len() {
                                if capabilities.at(k) == @expected_capability {
                                    found = true;
                                    break;
                                }
                            };
                            assert!(found, "Expected capability not found: {:?}", expected_capability);
                        }
                    } else if identity == @carol_id {
                        assert!(capabilities.len() == 0, "Expected 0 capabilities for carol");
                    } else {
                        panic!("Unexpected identity: {:?}", identity);
                    }
                }
            },
            Result::Err(error) => {
                panic!("Failed to retrieve privileges: {:?}", error);
            }
        }

        // Create test data
        let new_application = Application {
            id: 0x1234567890abcdef1234567890abcdef123456789.into(),
            blob: 0x1234567890abcdef1234567890abcdef123456789.into(),
            size: 0,
            source: "https://calimero.network",
            metadata: "Some metadata",
        };

        // Create a signed request
        bob_nonce += 1;
        let mut request = Request {
            signer_id: bob_id.clone(),
            nonce: bob_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::UpdateApplication(new_application.clone())
                }
            )
        };

        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);

        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = bob_key_pair.sign(hash).unwrap();

        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
        println!("Signed request: {:?}", signed_request);

        let mut signed_request_serialized = ArrayTrait::new();
        signed_request.serialize(ref signed_request_serialized);
        println!("Signed request serialized: {:?}", signed_request_serialized);

        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Entrypoint did not panic"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'missing privileges', *panic_data.at(0));
            }
        };

        match safe_dispatcher.application(context_id.clone()) {
            Result::Ok(result_application) => {
                assert(result_application.id == app_id, 'Incorrect application ID');
                assert(result_application.blob == app_blob, 'Incorrect application blob');
                assert(result_application.size == app_size, 'Incorrect application size');
                assert(result_application.source == app_source, 'Incorrect application source');
                assert(result_application.metadata == app_metadata, 'Incorrect application metadata');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve application: {:?}", error);
            }
        }

        // Create a signed request
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::UpdateApplication(new_application.clone())
                }
            )
        };
        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        let _res = spy_dispatcher.mutate(signed_request);

        spy.assert_emitted(
            @array![
                (
                    contract_address,
                    Event::ApplicationUpdated(
                        ApplicationUpdated { 
                            message: format!("Updated application for context `{}` from `{}` to `{}`", context_id, application.id, new_application.id) 
                        }
                    )
                ),
            ]
        );

        match safe_dispatcher.application(context_id.clone()) {
            Result::Ok(result_application) => {
                assert(result_application.id == new_application.id, 'Incorrect application ID');
                assert(result_application.blob == new_application.blob, 'Incorrect application blob');
                assert(result_application.size == new_application.size, 'Incorrect application size');
                assert(result_application.source == new_application.source, 'Incorrect application source');
                assert(result_application.metadata == new_application.metadata, 'Incorrect application metadata');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve application: {:?}", error);
            }
        }

        // Remove members
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest { 
                    context_id: context_id.clone(), 
                    kind: ContextRequestKind::RemoveMembers(array![bob_id]) 
                }
            )
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);

        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();

        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        let _res = spy_dispatcher.mutate(signed_request);

        spy.assert_emitted(
            @array![
                (
                    contract_address,
                    Event::MemberRemoved(
                        MemberRemoved { 
                            message: format!("Removed `{}` from being a member of `{}`", bob_id, context_id) 
                        }
                    )
                ),
            ]
        );

        match safe_dispatcher.privileges(context_id, array![]) {
            Result::Ok(privileges) => {
                for i in 0..privileges.len() {
                    let (identity, capabilities) = privileges.at(i);
                    if identity == @alice_id {
                        assert!(capabilities.len() == 2, "Expected 2 capabilities for alice");
                        let expected_capabilities = array![Capability::ManageApplication, Capability::ManageMembers];
                        for expected_capability in expected_capabilities {
                            let mut found = false;
                            for k in 0..capabilities.len() {
                                if capabilities.at(k) == @expected_capability {
                                    found = true;
                                    break;
                                }
                            };
                            assert!(found, "Expected capability not found: {:?}", expected_capability);
                        }
                    } else if identity == @carol_id {
                        assert!(capabilities.len() == 0, "Expected 0 capabilities for carol");
                    } else {
                        panic!("Unexpected identity: {:?}", identity);
                    }
                }
            },
            Result::Err(error) => {
                panic!("Failed to retrieve privileges: {:?}", error);
            }
        }

        // Verify that the members were added correctly
        match safe_dispatcher.members(context_id, 0, 10) {
            Result::Ok(members) => {
                assert(members.len() == 2, 'Incorrect number of members');
                assert(*members.at(0) == alice_id, 'Incorrect alice ID');
                assert(*members.at(1) == carol_id, 'Incorrect carol ID');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve members: {:?}", error);
            }
        }

        stop_cheat_caller_address(contract_address);

        // Remove members
        let mut request = Request {
            signer_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest { 
                    context_id: context_id.clone(), 
                    kind: ContextRequestKind::RemoveMembers(array![carol_id]) 
                }
            )
        };
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Entrypoint did not panic"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'Nonce mismatch', *panic_data.at(0));
            }
        };

        // Verify that the members are still here
        match safe_dispatcher.members(context_id, 0, 10) {
            Result::Ok(members) => {
                assert(members.len() == 2, 'Incorrect number of members');
                assert(*members.at(0) == alice_id, 'Incorrect alice ID');
                assert(*members.at(1) == carol_id, 'Incorrect carol ID');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve members: {:?}", error);
            }
        }

        stop_cheat_caller_address(contract_address);
    }
}
