// use snforge_std::signature::KeyPairTrait;

// use snforge_std::signature::secp256r1_curve::{Secp256r1CurveKeyPairImpl, Secp256r1CurveSignerImpl, Secp256r1CurveVerifierImpl};
// use snforge_std::signature::secp256k1_curve::{Secp256k1CurveKeyPairImpl, Secp256k1CurveSignerImpl, Secp256k1CurveVerifierImpl};
// use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl};


// use starknet::secp256r1::{Secp256r1Point};
// use starknet::secp256k1::{Secp256k1Point};

// // use starknet::secp256r1::{Secp256r1Point};
// // use starknet::secp256k1::{Secp256k1Point};
// use core::starknet::SyscallResultTrait;

// // #[test]
// fn test_using_curves() {
//     let msg_hash = 0x1f446d0850b5779b50c1e30ead2e5609614e94fe5d5598aa5459ee73c4f3604.into();
//     // Secp256r1
//     let key_pair = KeyPairTrait::<u256, Secp256r1Point>::generate();
//     let (r, s): (u256, u256) = key_pair.sign(msg_hash).unwrap();
//     let is_valid = key_pair.verify(msg_hash, (r, s));
    
//     // // Secp256k1
//     let key_pair2 = KeyPairTrait::<u256, Secp256k1Point>::generate();
//     let (r2, s2): (u256, u256) = key_pair2.sign(msg_hash).unwrap();
//     let is_valid2 = key_pair2.verify(msg_hash, (r2, s2));
    
//     // StarkCurve
//     let key_pair3 = KeyPairTrait::<felt252, felt252>::generate();
//     let (r3, s3): (felt252, felt252) = key_pair3.sign(msg_hash).unwrap();
//     let is_valid3 = key_pair3.verify(msg_hash, (r3, s3));
// }