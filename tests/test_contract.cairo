#[cfg(test)]
mod tests {
    use starknet::{ContractAddress, get_block_timestamp};
    use snforge_std::{
        declare, ContractClassTrait, DeclareResultTrait, 
        start_cheat_caller_address, stop_cheat_caller_address, EventSpyAssertionsTrait, spy_events,
    };
    use context_config::{
        Application, Signed, ContextId, RequestKind, Request, ContextRequestKind, ContextRequest,
        IContextConfigsDispatcher, IContextConfigsDispatcherTrait, IContextConfigsSafeDispatcherTrait, IContextConfigsSafeDispatcher,
        // IContextConfigsCheckerDispatcher, IContextConfigsCheckerDispatcherTrait
    };
    use context_config::types::{Event, ContextCreated};
    use core::traits::Into;
    use core::array::ArrayTrait;
    use core::clone::Clone;
    use core::byte_array::ByteArray;
    
    use snforge_std::signature::KeyPairTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl};
    // use core::starknet::SyscallResultTrait;

    use core::poseidon::PoseidonTrait;
    use core::poseidon::poseidon_hash_span;
    use core::hash::{HashStateTrait, HashStateExTrait};

    fn deploy_contract(name: ByteArray) -> ContractAddress {
        let contract = declare(name).unwrap().contract_class();

        let (contract_address, _) = contract.deploy(@array![]).unwrap();
        
        contract_address
    }

    #[test]
    fn test_application() {
        // Deploy the contract
        let contract_address = deploy_contract("ContextConfig");

        // Create a dispatcher
        let dispatcher = IContextConfigsDispatcher { contract_address };

        // Create a context ID
        let context_id: ContextId = 0x1f446d0850b5779b50c1e30ead2e5609614e94fe5d5598aa5459ee73c4f3604.into();

        // Call the application function
        let application = dispatcher.application(context_id);

        // Assert that we can retrieve an application (even if it's empty)
        assert(application.id == 0, 'Unexpected application ID');
        assert(application.blob == 0, 'Unexpected application blob');
        assert(application.size == 0, 'Unexpected application size');
        assert(application.source == "", 'Unexpected application source');
        assert(application.metadata == "", 'Unexpected application metadata');
    }

    #[test]
    #[feature("safe_dispatcher")]
    // #[should_panic(expected: "signer_id equals context_id")]
    fn test_add_context() {
        // Deploy the contract
        let contract_address = deploy_contract("ContextConfig");

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

        let context_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let context_public_key = context_key_pair.public_key;
        let context_id = context_public_key;

        // Create test data
        let application = Application {
            id: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
            blob: 0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(),
            size: 0,
            source: "https://calimero.network",
            metadata: "Some metadata",
        };

        // Create a signed request
        let mut request = Request {
            signer_id: alice_id.clone(),
            timestamp_ms: get_block_timestamp(),
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Add((context_id, application.clone()))
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

        let signed_request: Signed<Request> = Signed {
            payload: serialized,
            signature: (r, s),
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
            timestamp_ms: get_block_timestamp(),
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Add((alice_id, application.clone()))
                }
            )
        };

        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);

        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = context_key_pair.sign(hash).unwrap();

        let signed_request: Signed<Request> = Signed {
            payload: serialized,
            signature: (r, s),
        };

        // Call the mutate function
        let _res = spy_dispatcher.mutate(signed_request);

        // Assert that the context was created
        spy.assert_emitted(
            @array![
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


        // Start calling as node2 relayer
        start_cheat_caller_address(contract_address, node2_id);

         // Create a signed request
         let mut request = Request {
            signer_id: context_id.clone(),
            timestamp_ms: get_block_timestamp(),
            kind: RequestKind::Context(
                ContextRequest {
                    context_id: context_id.clone(),
                    kind: ContextRequestKind::Add((alice_id, application.clone()))
                }
            )
        };

        // Serialize the request
        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);

        // Hash the serialized request
        let hash = PoseidonTrait::new().update_with(poseidon_hash_span(serialized.span())).finalize();
        // Sign the hash
        let (r, s): (felt252, felt252) = context_key_pair.sign(hash).unwrap();

        let signed_request: Signed<Request> = Signed {
            payload: serialized,
            signature: (r, s),
        };

        // Call the mutate function
        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => panic!("Entrypoint did not panic"),
            Result::Err(panic_data) => {
                assert(*panic_data.at(0) == 'Context already exists', *panic_data.at(0));
            }
        };

        stop_cheat_caller_address(contract_address);

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

        let privileges = safe_dispatcher.privileges(context_id.clone(), array![]);
        println!("privileges: {:?}", privileges);
        // let (identity, capabilities) = privileges.at(0);
        // println!("identity: {:?}", identity);
        // println!("capabilities: {:?}", capabilities);
        // assert!(identity == @context_id, "Author ID does not match expected identity");
        // assert!(capabilities.len() > 0, "Expected capabilities for the author");

        // // Check specific capabilities
        // let expected_capabilities = array![Capability::ManageApplication, Capability::ManageMembers];
        // for expected_capability in expected_capabilities {
        //     let mut found = false;
        //     for k in 0..capabilities.len() {
        //         if capabilities.at(k) == @expected_capability {
        //             found = true;
        //             break;
        //         }
        //     };
        //     assert!(found, "Expected capability not found: {:?}", expected_capability);
        // }

        // // Verify that the author is a member of the context
        // let members = safe_dispatcher.members(context_id, 1, 2);
        // assert(members.len() == 1, 'Incorrect number of members');
        // assert(*members.at(0) == context_id, 'Incorrect author ID');

        // // Verify that the author has the correct privileges
        // let privileges = safe_dispatcher.privileges(context_id, array![context_id]);
        // let (identity, capabilities) = privileges.at(0);
        // assert!(identity == @context_id, "Author ID does not match expected identity");
        // assert!(capabilities.len() > 0, "Expected capabilities for the author");

        // // Check specific capabilities
        // let expected_capabilities = array![Capability::ManageApplication, Capability::ManageMembers];
        // for expected_capability in expected_capabilities {
        //     let mut found = false;
        //     for k in 0..capabilities.len() {
        //         if capabilities.at(k) == @expected_capability {
        //             found = true;
        //             break;
        //         }
        //     };
        //     assert!(found, "Expected capability not found: {:?}", expected_capability);
        // }
    }
}
