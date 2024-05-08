use crate::*;
use hex::FromHex;
use lazy_static::lazy_static;

lazy_static! {
    static ref AES_128_KEY: [u8; 16] =
        <[u8; 16]>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    static ref AES_192_KEY: [u8; 24] =
        <[u8; 24]>::from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
    static ref AES_256_KEY: [u8; 32] =
        <[u8; 32]>::from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
}

#[test]
fn expansion_of_128_bit_key() {
    let expanded = keygen_128(*AES_128_KEY);
    assert_eq!(expanded[0], 0x2b7e151628aed2a6abf7158809cf4f3c_u128.into());
    assert_eq!(expanded[1], 0xa0fafe1788542cb123a339392a6c7605_u128.into());
    assert_eq!(expanded[2], 0xf2c295f27a96b9435935807a7359f67f_u128.into());
    assert_eq!(expanded[3], 0x3d80477d4716fe3e1e237e446d7a883b_u128.into());
    assert_eq!(expanded[4], 0xef44a541a8525b7fb671253bdb0bad00_u128.into());
    assert_eq!(expanded[5], 0xd4d1c6f87c839d87caf2b8bc11f915bc_u128.into());
    assert_eq!(expanded[6], 0x6d88a37a110b3efddbf98641ca0093fd_u128.into());
    assert_eq!(expanded[7], 0x4e54f70e5f5fc9f384a64fb24ea6dc4f_u128.into());
    assert_eq!(expanded[8], 0xead27321b58dbad2312bf5607f8d292f_u128.into());
    assert_eq!(expanded[9], 0xac7766f319fadc2128d12941575c006e_u128.into());
    assert_eq!(expanded[10], 0xd014f9a8c9ee2589e13f0cc8b6630ca6_u128.into());
}

#[test]
fn expansion_of_192_bit_key() {
    let expanded = keygen_192(*AES_192_KEY);
    assert_eq!(expanded[0], 0x8e73b0f7da0e6452c810f32b809079e5_u128.into());
    assert_eq!(expanded[1], 0x62f8ead2522c6b7bfe0c91f72402f5a5_u128.into());
    assert_eq!(expanded[2], 0xec12068e6c827f6b0e7a95b95c56fec2_u128.into());
    assert_eq!(expanded[3], 0x4db7b4bd69b5411885a74796e92538fd_u128.into());
    assert_eq!(expanded[4], 0xe75fad44bb095386485af05721efb14f_u128.into());
    assert_eq!(expanded[5], 0xa448f6d94d6dce24aa326360113b30e6_u128.into());
    assert_eq!(expanded[6], 0xa25e7ed583b1cf9a27f939436a94f767_u128.into());
    assert_eq!(expanded[7], 0xc0a69407d19da4e1ec1786eb6fa64971_u128.into());
    assert_eq!(expanded[8], 0x485f703222cb8755e26d135233f0b7b3_u128.into());
    assert_eq!(expanded[9], 0x40beeb282f18a2596747d26b458c553e_u128.into());
    assert_eq!(expanded[10], 0xa7e1466c9411f1df821f750aad07d753_u128.into());
    assert_eq!(expanded[11], 0xca4005388fcc5006282d166abc3ce7b5_u128.into());
    assert_eq!(expanded[12], 0xe98ba06f448c773c8ecc720401002202_u128.into());
}

#[test]
fn expansion_of_256_bit_key() {
    let expanded = keygen_256(*AES_256_KEY);
    assert_eq!(expanded[0], 0x603deb1015ca71be2b73aef0857d7781_u128.into());
    assert_eq!(expanded[1], 0x1f352c073b6108d72d9810a30914dff4_u128.into());
    assert_eq!(expanded[2], 0x9ba354118e6925afa51a8b5f2067fcde_u128.into());
    assert_eq!(expanded[3], 0xa8b09c1a93d194cdbe49846eb75d5b9a_u128.into());
    assert_eq!(expanded[4], 0xd59aecb85bf3c917fee94248de8ebe96_u128.into());
    assert_eq!(expanded[5], 0xb5a9328a2678a647983122292f6c79b3_u128.into());
    assert_eq!(expanded[6], 0x812c81addadf48ba24360af2fab8b464_u128.into());
    assert_eq!(expanded[7], 0x98c5bfc9bebd198e268c3ba709e04214_u128.into());
    assert_eq!(expanded[8], 0x68007bacb2df331696e939e46c518d80_u128.into());
    assert_eq!(expanded[9], 0xc814e20476a9fb8a5025c02d59c58239_u128.into());
    assert_eq!(expanded[10], 0xde1369676ccc5a71fa2563959674ee15_u128.into());
    assert_eq!(expanded[11], 0x5886ca5d2e2f31d77e0af1fa27cf73c3_u128.into());
    assert_eq!(expanded[12], 0x749c47ab18501ddae2757e4f7401905a_u128.into());
    assert_eq!(expanded[13], 0xcafaaae3e4d59b349adf6acebd10190d_u128.into());
    assert_eq!(expanded[14], 0xfe4890d1e6188d0b046df344706c631e_u128.into());
}

macro_rules! aes_test {
    (enc: $enc:ident, $vectors:ident) => {
        assert_eq!($enc.encrypt_block($vectors[0].0), $vectors[0].1);
        assert_eq!($enc.encrypt_block($vectors[1].0), $vectors[1].1);

        assert_eq!(
            $enc.encrypt_2_blocks(AesBlockX2::from(($vectors[0].0, $vectors[1].0))),
            AesBlockX2::from(($vectors[0].1, $vectors[1].1))
        );

        assert_eq!($enc.encrypt_block($vectors[2].0), $vectors[2].1);
        assert_eq!($enc.encrypt_block($vectors[3].0), $vectors[3].1);

        assert_eq!(
            $enc.encrypt_2_blocks(AesBlockX2::from(($vectors[2].0, $vectors[3].0))),
            AesBlockX2::from(($vectors[2].1, $vectors[3].1))
        );

        assert_eq!(
            $enc.encrypt_4_blocks(AesBlockX4::from((
                $vectors[0].0,
                $vectors[1].0,
                $vectors[2].0,
                $vectors[3].0
            ))),
            AesBlockX4::from(($vectors[0].1, $vectors[1].1, $vectors[2].1, $vectors[3].1))
        );
    };
    (dec: $enc:ident, $vectors:ident) => {
        assert_eq!($enc.decrypt_block($vectors[0].1), $vectors[0].0);
        assert_eq!($enc.decrypt_block($vectors[1].1), $vectors[1].0);

        assert_eq!(
            $enc.decrypt_2_blocks(AesBlockX2::from(($vectors[0].1, $vectors[1].1))),
            AesBlockX2::from(($vectors[0].0, $vectors[1].0))
        );

        assert_eq!($enc.decrypt_block($vectors[2].1), $vectors[2].0);
        assert_eq!($enc.decrypt_block($vectors[3].1), $vectors[3].0);

        assert_eq!(
            $enc.decrypt_2_blocks(AesBlockX2::from(($vectors[2].1, $vectors[3].1))),
            AesBlockX2::from(($vectors[2].0, $vectors[3].0))
        );

        assert_eq!(
            $enc.decrypt_4_blocks(AesBlockX4::from((
                $vectors[0].1,
                $vectors[1].1,
                $vectors[2].1,
                $vectors[3].1
            ))),
            AesBlockX4::from(($vectors[0].0, $vectors[1].0, $vectors[2].0, $vectors[3].0))
        );
    };
}

// these are of form (plaintext, ciphertext) pairs
lazy_static! {
    static ref AES_128_VECTORS: [(AesBlock, AesBlock); 5] = [
        (
            0x6bc1bee22e409f96e93d7e117393172a.into(),
            0x3ad77bb40d7a3660a89ecaf32466ef97.into()
        ),
        (
            0xae2d8a571e03ac9c9eb76fac45af8e51.into(),
            0xf5d3d58503b9699de785895a96fdbaaf.into()
        ),
        (
            0x30c81c46a35ce411e5fbc1191a0a52ef.into(),
            0x43b1cd7f598ece23881b00e3ed030688.into()
        ),
        (
            0xf69f2445df4f9b17ad2b417be66c3710.into(),
            0x7b0c785e27e8ad3f8223207104725dd4.into()
        ),
        (
            0x3243f6a8885a308d313198a2e0370734.into(),
            0x3925841d02dc09fbdc118597196a0b32.into()
        ),
    ];
    static ref AES_192_VECTORS: [(AesBlock, AesBlock); 4] = [
        (
            0x6bc1bee22e409f96e93d7e117393172a.into(),
            0xbd334f1d6e45f25ff712a214571fa5cc.into()
        ),
        (
            0xae2d8a571e03ac9c9eb76fac45af8e51.into(),
            0x974104846d0ad3ad7734ecb3ecee4eef.into()
        ),
        (
            0x30c81c46a35ce411e5fbc1191a0a52ef.into(),
            0xef7afd2270e2e60adce0ba2face6444e.into()
        ),
        (
            0xf69f2445df4f9b17ad2b417be66c3710.into(),
            0x9a4b41ba738d6c72fb16691603c18e0e.into()
        )
    ];
    static ref AES_256_VECTORS: [(AesBlock, AesBlock); 4] = [
        (
            0x6bc1bee22e409f96e93d7e117393172a.into(),
            0xf3eed1bdb5d2a03c064b5a7e3db181f8.into()
        ),
        (
            0xae2d8a571e03ac9c9eb76fac45af8e51.into(),
            0x591ccb10d410ed26dc5ba74a31362870.into()
        ),
        (
            0x30c81c46a35ce411e5fbc1191a0a52ef.into(),
            0xb6ed21b99ca6f4f9f153e7b1beafed1d.into()
        ),
        (
            0xf69f2445df4f9b17ad2b417be66c3710.into(),
            0x23304b7a39f9f3ff067d8d8f9e24ecc7.into()
        )
    ];
}

#[test]
fn aes_128_test() {
    let enc = Aes128Enc::from(*AES_128_KEY);

    aes_test!(enc: enc, AES_128_VECTORS);
    assert_eq!(
        enc.encrypt_block(AES_128_VECTORS[4].0),
        AES_128_VECTORS[4].1
    );

    let dec = enc.decrypter();

    aes_test!(dec: dec, AES_128_VECTORS);
    assert_eq!(
        dec.decrypt_block(AES_128_VECTORS[4].1),
        AES_128_VECTORS[4].0
    );
}

#[test]
fn aes_192_test() {
    let enc = Aes192Enc::from(*AES_192_KEY);

    aes_test!(enc: enc, AES_192_VECTORS);

    let dec = enc.decrypter();

    aes_test!(dec: dec, AES_192_VECTORS);
}

#[test]
fn aes_256_test() {
    let enc = Aes256Enc::from(*AES_256_KEY);

    aes_test!(enc: enc, AES_256_VECTORS);

    let dec = enc.decrypter();

    aes_test!(dec: dec, AES_256_VECTORS);
}
