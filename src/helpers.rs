use elastic_elgamal::{Ciphertext, group::Ristretto, PublicKey, VerifiableDecryption, LogEqualityProof, CandidateDecryption};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{to_binary, Addr, CosmosMsg, StdResult, WasmMsg};

use crate::msg::{ExecuteMsg, Decryption};
use base64::{engine::general_purpose, Engine};
use elastic_elgamal::group::{ElementOps};

/// CwTemplateContract is a wrapper around Addr that provides a lot of helpers
/// for working with this.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct CwTemplateContract(pub Addr);

impl CwTemplateContract {
    pub fn addr(&self) -> Addr {
        self.0.clone()
    }

    pub fn call<T: Into<ExecuteMsg>>(&self, msg: T) -> StdResult<CosmosMsg> {
        let msg = to_binary(&msg.into())?;
        Ok(WasmMsg::Execute {
            contract_addr: self.addr().into(),
            msg,
            funds: vec![],
        }
        .into())
    }
}

pub fn from_base64(val: &String) -> Vec<u8> {
    let mut buffer = Vec::<u8>::new();
    let decoded_size = general_purpose::URL_SAFE_NO_PAD.decode_vec(val, &mut buffer).unwrap();
    buffer
}

pub fn to_base64(val: Vec<u8>) -> String {
    let mut buffer = Vec::<u8>::new();
    buffer.resize( val.len() * 4 / 3 + 4, 0);
    let encoded_size = general_purpose::URL_SAFE_NO_PAD.encode_slice(val.as_slice(), &mut buffer).unwrap();
    String::from_utf8(buffer.as_slice()[0..encoded_size].to_vec()).unwrap()
}

pub fn deserialize_encrypted_vote(ciphertexts: Vec<Vec<String>>) -> Vec<Ciphertext<Ristretto>> {
    ciphertexts.iter().map(|item|  {
        let random_element_bytes = from_base64(item.get(0).unwrap());
        let blinded_element_bytes = from_base64(item.get(1).unwrap());
        let random_element = Ristretto::deserialize_element(&random_element_bytes).unwrap();
        let blinded_element = Ristretto::deserialize_element(&blinded_element_bytes).unwrap();
        Ciphertext::new(random_element, blinded_element)
    }).collect()
}

pub fn serialize_encrypted_vote(encrypted_choices: Vec<Ciphertext<Ristretto>>) -> Vec<Vec<String>> {
    encrypted_choices.iter().map(|item|  {
        let random_element = element_to_base64((item.random_element().clone()));
        let blined_element = element_to_base64((item.blinded_element().clone()));
        vec![random_element, blined_element]
    }).collect()
}

pub fn element_to_base64(val: <Ristretto as ElementOps>::Element) -> String {
    let mut buffer = Vec::<u8>::new();
    buffer.resize( 32, 0);
    Ristretto::serialize_element(&val, &mut buffer);
    to_base64(buffer)
}

pub fn to_public_key(val: String) -> PublicKey<Ristretto> {
    PublicKey::<Ristretto>::from_bytes(from_base64(&val).as_slice()).unwrap()
}

pub fn deserialize_decryption(decryption: Decryption) -> (Vec<CandidateDecryption<Ristretto>>, Vec<LogEqualityProof<Ristretto>>) {
    let mut candidate_decryptions = vec![];
    let mut proofs = vec![];
    for (index, decryption_str) in decryption.verifiable_decryptions.iter().enumerate() {
        candidate_decryptions.push(CandidateDecryption::<Ristretto>::from_bytes(from_base64(decryption_str).as_slice()).unwrap());
        proofs.push(LogEqualityProof::<Ristretto>::from_bytes(from_base64(decryption.proofs.get(index).unwrap()).as_slice()).unwrap());
    }
    (candidate_decryptions, proofs)
}

pub fn serialize_decryption(verifiable_decryptions: Vec<VerifiableDecryption<Ristretto>>, proofs: Vec<LogEqualityProof<Ristretto>>) -> Decryption {
    assert!(verifiable_decryptions.len() == proofs.len(), "Decryptions and proofs should have equal length");
    let mut serialized_decryptions = vec![];
    let mut serialized_proofs = vec![];
    for (index, verifiable_decryption) in verifiable_decryptions.iter().enumerate() {
        serialized_decryptions.push(to_base64(verifiable_decryption.to_bytes().to_vec()));
        let proof = proofs.get(index).unwrap();
        serialized_proofs.push(to_base64(proof.to_bytes().to_vec()));
    }
    Decryption { 
        verifiable_decryptions: serialized_decryptions, 
        proofs: serialized_proofs 
    }
}
