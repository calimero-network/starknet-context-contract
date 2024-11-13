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
        ApplicationId,
        ApplicationBlob,
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
        ContextId,
        ContextIdentity,
    };
    use core::traits::Into;
    // use core::traits::{Mul, Sub};
    use core::array::ArrayTrait;
    use core::clone::Clone;
    use core::byte_array::ByteArray;

    use snforge_std::signature::KeyPairTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl};

    use core::poseidon::poseidon_hash_span;

    fn deploy_contract(name: ByteArray) -> (ContractAddress, ContractAddress) {
        let owner: ContractAddress = starknet::contract_address_const::<0x123456789>();

        let mut constructor_calldata = ArrayTrait::new();
        constructor_calldata.append(owner.into());
    
        let contract = declare(name).unwrap().contract_class();
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
    
        (contract_address, owner)
    }

    fn split_felt252(value: felt252) -> (felt252, felt252) {
        // The constant 2^128 as a felt252
        let split_point: felt252 = 0x100000000000000000000000000000000.into();
        
        // Get the high part by multiplying by the inverse of split_point
        // This is equivalent to division in the finite field
        let high = value * 0x2_u128.into(); // TODO: Calculate correct inverse
        
        // Get the low part by subtracting (high * split_point) from value
        let low = value - (high * split_point);
        
        (high, low)
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

        // Create identities for test users
        let alice_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let alice_public_key = alice_key_pair.public_key;
        let (alice_high, alice_low) = split_felt252(alice_public_key);
        let alice_id = ContextIdentity { high: alice_high, low: alice_low };
        let mut alice_nonce = 0;

        let bob_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let bob_public_key = bob_key_pair.public_key;
        let (bob_high, bob_low) = split_felt252(bob_public_key);
        let bob_id = ContextIdentity { high: bob_high, low: bob_low };
        let mut bob_nonce = 0;

        let carol_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let carol_public_key = carol_key_pair.public_key;
        let (carol_high, carol_low) = split_felt252(carol_public_key);
        let carol_id = ContextIdentity { high: carol_high, low: carol_low };

        let context_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let context_public_key = context_key_pair.public_key;
        let (context_high, context_low) = split_felt252(context_public_key);
        let context_id = ContextId { high: context_high, low: context_low };
        let context_identity = ContextIdentity { high: context_high, low: context_low };

        // // Create a signed request
        // let mut request = Request {
        //     signer_id: alice_id.clone(),
        //     user_id: alice_id.clone(),
        //     nonce: alice_nonce,
        //     kind: RequestKind::Context(
        //         ContextRequest {
        //             context_id: context_id.clone(),
        //             kind: ContextRequestKind::Add((
        //                 alice_id.clone(),
        //                 Application {
        //                     id: ApplicationId {
        //                         high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
        //                         low: 0xe128229d757014c458e561679c42baf.into()
        //                     },
        //                     blob: ApplicationBlob {
        //                         high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
        //                         low: 0xe128229d757014c458e561679c42baf.into()
        //                     },
        //                     size: 0,
        //                     source: "https://calimero.network",
        //                     metadata: "Some metadata",
        //                 }
        //             ))
        //         }
        //     )
        // };

        // println!("request: {:?}", request);
        // // Serialize the request
        // let mut serialized = ArrayTrait::new();
        // request.serialize(ref serialized);
        // // Hash the serialized request
        // // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // let hash = poseidon_hash_span(serialized.span());
        // // Sign the hash
        // let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        // let signed_request: Signed = Signed {
        //     payload: serialized,
        //     signature_r: r,
        //     signature_s: s,
        // };

        // println!("signed_request: {:?}", signed_request);
        
        // // Call as node1 relayer
        // start_cheat_caller_address(contract_address, node1_id);
        // // Call the mutate function
        // match safe_dispatcher.mutate(signed_request) {
        //     Result::Ok(_) => panic!("Entrypoint did not panic"),
        //     Result::Err(panic_data) => {
        //         assert(*panic_data.at(0) == 'signer_id equals context_id', *panic_data.at(0));
        //     }
        // };

        // Create a signed request
        let mut request = Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Add((
                        alice_id, 
                        Application {
                            id: ApplicationId {
                                high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
                                low: 0xe128229d757014c458e561679c42baf.into()
                            },
                            blob: ApplicationBlob {
                                high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
                                low: 0xe128229d757014c458e561679c42baf.into()
                            },
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
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
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
                        MemberAdded { 
                            message: format!(
                                "Added member ({}, {}) to context ({}, {})", 
                                alice_id.high, alice_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
                    )
                ),
                (
                    contract_address,
                    Event::CapabilityGranted(
                        CapabilityGranted { 
                            message: format!(
                                "Granted ManageMembers to member ({}, {}) in context ({}, {})", 
                                alice_id.high, alice_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
                    )
                ),
                (
                    contract_address,
                    Event::CapabilityGranted(
                        CapabilityGranted { 
                            message: format!(
                                "Granted ManageApplication to member ({}, {}) in context ({}, {})", 
                                alice_id.high, alice_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
                    )
                ),
                (
                    contract_address,
                    Event::ContextCreated(
                        ContextCreated { 
                            message: format!(
                                "Context ({}, {}) created with author ({}, {})", 
                                context_id.high, context_id.low,
                                alice_id.high, alice_id.low
                            ) 
                        }
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
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Add((
                        alice_id, 
                        Application {
                            id: ApplicationId {
                                high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
                                low: 0xe128229d757014c458e561679c42baf.into()
                            },
                            blob: ApplicationBlob {
                                high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
                                low: 0xe128229d757014c458e561679c42baf.into()
                            },
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
        // println!("serialized: {:?}", serialized);

        // Hash the serialized request
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
        // println!("hash: {:?}", hash);
        // Sign the hash
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();

        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        let mut serialized_signed_request = ArrayTrait::new();
        signed_request.serialize(ref serialized_signed_request);
        // println!("serialized_signed_request: {:?}", serialized_signed_request);

        // Call the mutate function
        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Entrypoint did not panic"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'Context already exists', *panic_data.at(0));
            }
        };

        stop_cheat_caller_address(contract_address);

        let application = Application {
            id: ApplicationId {
                high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
                low: 0xe128229d757014c458e561679c42baf.into()
            },
            blob: ApplicationBlob {
                high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
                low: 0xe128229d757014c458e561679c42baf.into()
            },
            size: 0,
            source: "https://calimero.network",
            metadata: "Some metadata",
        };

        let app_clone = application.clone();
            
        // Store the application values for later comparison
        let app_id = app_clone.id;
        let app_blob = app_clone.blob;
        let app_size = app_clone.size;
        let app_source = app_clone.source.clone();
        let app_metadata = app_clone.metadata.clone();

        println!("app_id: {:?}", app_id);

        // Verify that the context was added correctly
        match safe_dispatcher.application(context_id.clone()) {
            Result::Ok(result_application) => {
                let application = result_application.unwrap();
                assert(application.id == app_id, 'Incorrect application ID');
                assert(application.blob == app_blob, 'Incorrect application blob');
                assert(application.size == app_size, 'Incorrect application size');
                assert(application.source == app_source, 'Incorrect application source');
                assert(application.metadata == app_metadata, 'Incorrect application metadata');
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
                let first_member = *members.at(0);
                assert(
                    first_member.high == alice_id.high && first_member.low == alice_id.low, 
                    'Incorrect author ID'
                );
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
            user_id: alice_id.clone(),
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
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
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
                        MemberAdded { 
                            message: format!(
                                "Added member ({}, {}) to context ({}, {})", 
                                alice_id.high, alice_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
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
            user_id: bob_id.clone(),
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
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
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
                assert(*panic_data.at(0) == 'Unauthorized', *panic_data.at(0));
            }
        };

        // Create a signed request
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
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
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
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
                    Event::CapabilityGranted(
                        CapabilityGranted { 
                            message: format!(
                                "Granted ManageMembers to member ({}, {}) in context ({}, {})", 
                                bob_id.high, bob_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
                    )
                ),
            ]
        );

        // Create a signed request
        bob_nonce += 1;
        let mut request = Request {
            signer_id: bob_id.clone(),
            user_id: bob_id.clone(),
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
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
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
                    Event::MemberAdded(
                        MemberAdded { 
                            message: format!(
                                "Added member ({}, {}) to context ({}, {})", 
                                carol_id.high, carol_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
                    )
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
            id: ApplicationId {
                high: 0x1234567890abcdef1234567890.into(),
                low: 0xabcdef123456789.into()
            },
            blob: ApplicationBlob {
                high: 0x1234567890abcdef1234567890.into(),
                low: 0xabcdef123456789.into()
            },
            size: 0,
            source: "https://calimero.network",
            metadata: "Some metadata",
        };

        // Create a signed request
        bob_nonce += 1;
        let mut request = Request {
            signer_id: bob_id.clone(),
            user_id: bob_id.clone(),
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
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
        // Sign the hash
        let (r, s): (felt252, felt252) = bob_key_pair.sign(hash).unwrap();

        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
        // println!("Signed request: {:?}", signed_request);

        let mut signed_request_serialized = ArrayTrait::new();
        signed_request.serialize(ref signed_request_serialized);
        // println!("Signed request serialized: {:?}", signed_request_serialized);

        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Entrypoint did not panic"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'Unauthorized', *panic_data.at(0));
            }
        };

        match safe_dispatcher.application(context_id.clone()) {
            Result::Ok(result_application) => {
                let application = result_application.unwrap();
                assert(application.id == app_id, 'Incorrect application ID');
                assert(application.blob == app_blob, 'Incorrect application blob');
                assert(application.size == app_size, 'Incorrect application size');
                assert(application.source == app_source, 'Incorrect application source');
                assert(application.metadata == app_metadata, 'Incorrect application metadata');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve application: {:?}", error);
            }
        }
/////
        // Create a signed request
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
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
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
        // Sign the hash
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        let _res = spy_dispatcher.mutate(signed_request);

        let old_application = application.clone();

        spy.assert_emitted(
            @array![
                (
                    contract_address,
                    Event::ApplicationUpdated(
                        ApplicationUpdated { 
                            message: format!(
                                "Updated application for context ({}, {}) from ({}, {}) to ({}, {})", 
                                context_id.high, context_id.low,
                                old_application.id.high, old_application.id.low,
                                new_application.id.high, new_application.id.low
                            ) 
                        }
                    )
                ),
            ]
        );

        match safe_dispatcher.application(context_id.clone()) {
            Result::Ok(result_application) => {
                let application = result_application.unwrap();
                assert(application.id == new_application.id, 'Incorrect application ID');
                assert(application.blob == new_application.blob, 'Incorrect application blob');
                assert(application.size == new_application.size, 'Incorrect application size');
                assert(application.source == new_application.source, 'Incorrect application source');
                assert(application.metadata == new_application.metadata, 'Incorrect application metadata');
            },
            Result::Err(error) => {
                panic!("Failed to retrieve application: {:?}", error);
            }
        }

        // Remove members
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
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

        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
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
                            message: format!(
                                "Removed member ({}, {}) from context ({}, {})", 
                                bob_id.high, bob_id.low, context_id.high, context_id.low
                            ) 
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

        // // Remove members
        // let mut request = Request {
        //     signer_id: alice_id.clone(),
        //     user_id: alice_id.clone(),
        //     nonce: alice_nonce,
        //     kind: RequestKind::Context(
        //         ContextRequest { 
        //             context_id: context_id.clone(), 
        //             kind: ContextRequestKind::RemoveMembers(array![carol_id]) 
        //         }
        //     )
        // };
        // let mut serialized = ArrayTrait::new();
        // request.serialize(ref serialized);
        // // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // let hash = poseidon_hash_span(serialized.span());
        // let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        // let signed_request: Signed = Signed {
        //     payload: serialized,
        //     signature_r: r,
        //     signature_s: s,
        // };

        // match safe_dispatcher.mutate(signed_request) {
        //     Result::Ok(_) => panic!("Entrypoint did not panic"),
        //     Result::Err(panic_data) => {
        //         assert(*panic_data.at(0) == 'Nonce mismatch', *panic_data.at(0));
        //     }
        // };

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

        // Remove members
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
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
        // let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        let hash = poseidon_hash_span(serialized.span());
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
                            message: format!(
                                "Removed member ({}, {}) from context ({}, {})", 
                                carol_id.high, carol_id.low, context_id.high, context_id.low
                            ) 
                        }
                    )
                ),
            ]
        );

        stop_cheat_caller_address(contract_address);

        // Add members test
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::AddMembers(array![bob_id.clone(), carol_id.clone()])
                }
            )
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        let _res = spy_dispatcher.mutate(signed_request);

        // Assert events for added members
        spy.assert_emitted(
            @array![
                (
                    contract_address,
                    Event::MemberAdded(
                        MemberAdded { 
                            message: format!(
                                "Added member ({}, {}) to context ({}, {})", 
                                bob_id.high, bob_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
                    )
                ),
                (
                    contract_address,
                    Event::MemberAdded(
                        MemberAdded { 
                            message: format!(
                                "Added member ({}, {}) to context ({}, {})", 
                                carol_id.high, carol_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
                    )
                )
            ]
        );

        // Verify privileges
        match safe_dispatcher.privileges(context_id, array![]) {
            Result::Ok(privileges) => {
                for i in 0..privileges.len() {
                    let (identity, capabilities) = privileges.at(i);
                    if identity.high == @alice_id.high && identity.low == @alice_id.low {
                        assert!(capabilities.len() == 2, "Expected 2 capabilities for alice");
                        let expected_capabilities = array![
                            Capability::ManageApplication, 
                            Capability::ManageMembers
                        ];
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
                    } else if identity.high == @bob_id.high && identity.low == @bob_id.low {
                        assert!(capabilities.len() == 0, "Expected 0 capabilities for bob");
                    } else if identity.high == @carol_id.high && identity.low == @carol_id.low {
                        assert!(capabilities.len() == 0, "Expected 0 capabilities for carol");
                    } else {
                        panic!("Unexpected identity: ({}, {})", identity.high, identity.low);
                    }
                }
            },
            Result::Err(error) => {
                panic!("Failed to retrieve privileges: {:?}", error);
            }
        }

        // Test updating application
        let new_application = Application {
            id: ApplicationId {
                high: 0x1234567890abcdef1234567890.into(),
                low: 0xabcdef123456789.into()
            },
            blob: ApplicationBlob {
                high: 0x1234567890abcdef1234567890.into(),
                low: 0xabcdef123456789.into()
            },
            size: 0,
            source: "https://calimero.network",
            metadata: "Some metadata",
        };

        // Reset bob's nonce since he was removed from the context
        bob_nonce = 0; 
        // Try updating application with bob (should fail due to lack of privileges)
        let mut request = Request {
            signer_id: bob_id.clone(),
            user_id: bob_id.clone(),
            nonce: 0,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::UpdateApplication(new_application.clone())
                }
            )
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = bob_key_pair.sign(hash).unwrap();
        let signed_request: Signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Expected failure due to missing privileges"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'Unauthorized', *panic_data.at(0));
            }
        };

        // Try updating application with alice (should succeed)
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::UpdateApplication(new_application.clone())
                }
            )
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = poseidon_hash_span(serialized.span());
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
                            message: format!(
                                "Updated application for context ({}, {}) from ({}, {}) to ({}, {})", 
                                context_id.high, context_id.low,
                                application.id.high, application.id.low,
                                new_application.id.high, new_application.id.low
                            ) 
                        }
                    )
                ),
            ]
        );

        // Remove bob as member
        alice_nonce += 1;
        let mut request = Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: RequestKind::Context(
                ContextRequest { 
                    context_id: context_id.clone(), 
                    kind: ContextRequestKind::RemoveMembers(array![bob_id.clone()]) 
                }
            )
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = poseidon_hash_span(serialized.span());
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
                            message: format!(
                                "Removed member ({}, {}) from context ({}, {})", 
                                bob_id.high, bob_id.low,
                                context_id.high, context_id.low
                            ) 
                        }
                    )
                ),
            ]
        );

        // Verify final member list
        match safe_dispatcher.members(context_id, 0, 10) {
            Result::Ok(members) => {
                assert(members.len() == 2, 'Incorrect number of members');
                let first_member = *members.at(0);
                let second_member = *members.at(1);
                
                // Check alice is still present
                assert(
                    first_member.high == alice_id.high && first_member.low == alice_id.low,
                    'Alice should still be a member'
                );
                
                // Check carol is still present
                assert(
                    second_member.high == carol_id.high && second_member.low == carol_id.low,
                    'Carol should still be a member'
                );
            },
            Result::Err(error) => {
                panic!("Failed to retrieve members: {:?}", error);
            }
        }

        // // Try to remove carol with incorrect nonce (should fail)
        // let mut request = Request {
        //     signer_id: alice_id.clone(),
        //     user_id: alice_id.clone(),
        //     nonce: alice_nonce, // Using same nonce again
        //     kind: RequestKind::Context(
        //         ContextRequest { 
        //             context_id: context_id.clone(), 
        //             kind: ContextRequestKind::RemoveMembers(array![carol_id.clone()]) 
        //         }
        //     )
        // };

        // let mut serialized = ArrayTrait::new();
        // request.serialize(ref serialized);
        // let hash = poseidon_hash_span(serialized.span());
        // let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        // let signed_request: Signed = Signed {
        //     payload: serialized,
        //     signature_r: r,
        //     signature_s: s,
        // };

        // match safe_dispatcher.mutate(signed_request) {
        //     Result::Ok(_) => panic!("Expected failure due to nonce mismatch"),
        //     Result::Err(panic_data) => {
        //         assert(*panic_data.at(0) == 'Nonce mismatch', *panic_data.at(0));
        //     }
        // };

        // Verify members haven't changed after failed removal
        match safe_dispatcher.members(context_id, 0, 10) {
            Result::Ok(members) => {
                assert(members.len() == 2, 'Incorrect number of members');
                let first_member = *members.at(0);
                let second_member = *members.at(1);
                
                assert(
                    first_member.high == alice_id.high && first_member.low == alice_id.low,
                    'Alice should still be a member'
                );
                assert(
                    second_member.high == carol_id.high && second_member.low == carol_id.low,
                    'Carol should still be a member'
                );
            },
            Result::Err(error) => {
                panic!("Failed to retrieve members: {:?}", error);
            }
        }

        // Final verification of privileges
        match safe_dispatcher.privileges(context_id, array![]) {
            Result::Ok(privileges) => {
                for i in 0..privileges.len() {
                    let (identity, capabilities) = privileges.at(i);
                    if identity.high == @alice_id.high && identity.low == @alice_id.low {
                        assert!(capabilities.len() == 2, "Alice should have 2 capabilities");
                        let expected_capabilities = array![
                            Capability::ManageApplication, 
                            Capability::ManageMembers
                        ];
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
                    } else if identity.high == @carol_id.high && identity.low == @carol_id.low {
                        assert!(capabilities.len() == 0, "Carol should have no capabilities");
                    } else {
                        panic!(
                            "Unexpected identity: ({}, {})", 
                            identity.high, identity.low
                        );
                    }
                }
            },
            Result::Err(error) => {
                panic!("Failed to retrieve privileges: {:?}", error);
            }
        }
    }
}
