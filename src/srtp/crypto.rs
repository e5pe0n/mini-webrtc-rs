use aes::Aes128;
use aes::cipher::{BlockEncrypt, generic_array::GenericArray};
use aes_gcm::{Aes128Gcm, Key, KeyInit};

pub struct SrtpGcm {
    srtp_gcm: Aes128Gcm,
    srtcp_gcm: Aes128Gcm,
    srtp_salt: Vec<u8>,
    srtcp_salt: Vec<u8>,
}

impl SrtpGcm {
    pub fn new(master_key: &[u8], master_salt: &[u8]) -> Self {
        let srtp_key = aes_cm_key_derivation(
            KeyDerivationLabel::SrtpEncryptionKey,
            master_key,
            master_salt,
        );
        let srtp_salt =
            aes_cm_key_derivation(KeyDerivationLabel::SrtpSaltingKey, master_key, master_salt);
        let srtcp_key = aes_cm_key_derivation(
            KeyDerivationLabel::SrtcpEncryptionKey,
            master_key,
            master_salt,
        );
        let srtcp_salt =
            aes_cm_key_derivation(KeyDerivationLabel::SrtcpSaltingKey, master_key, master_salt);

        Self {
            srtp_gcm: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&srtp_key)),
            srtcp_gcm: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&srtcp_key)),
            srtp_salt,
            srtcp_salt,
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc3711#section-4.3.1
enum KeyDerivationLabel {
    SrtpEncryptionKey = 0x00,
    SrtpSaltingKey = 0x02,
    SrtcpEncryptionKey = 0x03,
    SrtcpSaltingKey = 0x05,
}

fn aes_cm_key_derivation(
    label: KeyDerivationLabel,
    master_key: &[u8],
    master_salt: &[u8],
) -> Vec<u8> {
    // https://datatracker.ietf.org/doc/html/rfc3711#section-5.3
    // https://datatracker.ietf.org/doc/html/rfc3711#autoid-26
    // https://datatracker.ietf.org/doc/html/rfc3711#autoid-17
    // index DIV kdr:                 000000000000
    // label:                       00
    // master salt:   0EC675AD498AFEEBB6960B3AABE6
    // -----------------------------------------------
    // xor:           0EC675AD498AFEEBB6960B3AABE6     (x, PRF input)
    // x*2^16:        0EC675AD498AFEEBB6960B3AABE60000 (AES-CM input)
    let key_length = match label {
        KeyDerivationLabel::SrtpEncryptionKey => master_key.len(),
        KeyDerivationLabel::SrtpSaltingKey => master_salt.len(),
        KeyDerivationLabel::SrtcpEncryptionKey => master_key.len(),
        KeyDerivationLabel::SrtcpSaltingKey => master_salt.len(),
    };
    let mut x = vec![0u8; master_key.len()];
    x[0..master_salt.len()].copy_from_slice(master_salt);
    x[7] ^= label as u8;

    let block = Aes128::new(Key::<Aes128>::from_slice(&master_key));

    let num_iters = (key_length + master_key.len()) / master_key.len();
    let mut key = vec![0u8; num_iters * master_key.len()];
    for i in 0..num_iters {
        x[master_key.len() - 2..].copy_from_slice(&i.to_be_bytes());
        let ki = GenericArray::from_mut_slice(
            &mut key[i * master_key.len()..(i * 1) * master_key.len()],
        );
        block.encrypt_block(ki);
    }
    key
}
