use std::borrow::BorrowMut;

#[cfg(not(feature = "library"))]
use cosmwasm_std::{entry_point, to_binary};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, QueryResponse};
use elastic_elgamal::app::{EncryptedChoice, SingleChoice};
use elastic_elgamal::{Ciphertext, RingProof, LogEqualityProof};
use elastic_elgamal::group::{Ristretto, ElementOps};
// use cw2::set_contract_version;

use crate::error::ContractError;
use crate::helpers::from_base64;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, PollResponse};
use crate::state::{POLL_PUB_KEY, POLL, ENCRYPTED_VOTE, TOTAL_VOTES};
use crate::helpers::{serialize_encrypted_vote, deserialize_encrypted_vote};


/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw-poll";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

/**
 * 1. Instantiate: Create a poll, question, choices, single or multi, start time, end time
 * 2. SetupKey: 
 * 3. Vote:
 * 4. Decrypt: 
 */

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    match POLL_PUB_KEY.save(deps.storage, &msg.poll_public_key) {
        Ok(_) => Ok(Response::default()),
        Err(e) => Err(ContractError::StateError{  })
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SetupPoll { poll_details }  => setup_poll(deps, env, poll_details),
        ExecuteMsg::AddVote { vote } => add_vote(deps, env, vote),
        ExecuteMsg::SubmitDecryptedTally {poll_tally} => submit_decrypted_tally(deps, env, poll_tally)
    }
}

fn setup_poll(deps: DepsMut, env: Env, poll_details: crate::msg::Poll) -> Result<Response, ContractError> {
    // Store the poll
    POLL.save(deps.storage, &poll_details);
    // TODO: Do validations
    Ok(Response::default())
}

fn add_vote(deps: DepsMut, env: Env, vote: crate::msg::Vote) -> Result<Response, ContractError> {
    // 1. Convert vote from base64 string to bytes
    
    let encrypted_choices = deserialize_encrypted_vote(vote.ciphertexts.clone());

    let range_proof = RingProof::<Ristretto>::from_bytes(from_base64(&vote.range_proof).as_slice()).unwrap();

    let sum_proof = LogEqualityProof::<Ristretto>::from_bytes(from_base64(&vote.sum_proof).as_slice()).unwrap();

    let encrypted_choice = EncryptedChoice::<Ristretto, SingleChoice>::new_encrypted_choice(encrypted_choices.clone(), range_proof, sum_proof);

    // TODO: Verify encrypted choice proofs for single / multiple

    // Sum and store the vote
    if (ENCRYPTED_VOTE.exists(deps.storage)) {
        let stored_tally = ENCRYPTED_VOTE.load(deps.storage).unwrap();
        let encrypted_tally = deserialize_encrypted_vote(stored_tally);
        let mut encrypted_sum: Vec<Ciphertext<Ristretto>> = Vec::new();
        for (index, value) in encrypted_tally.iter().enumerate() {
            let choice = *encrypted_choices.get(index).unwrap();
            let sum_choice = choice + *value;
            encrypted_sum.push(sum_choice);
        }
        let serialized_sum = serialize_encrypted_vote(encrypted_sum);
        ENCRYPTED_VOTE.save(deps.storage, &serialized_sum);
        // Check for errors
    } else {
        ENCRYPTED_VOTE.save(deps.storage, &vote.ciphertexts);
        // Check for errors
    }

    Ok(Response::default())
}


fn submit_decrypted_tally(deps: DepsMut, env: Env, tally: crate::msg::PollTally) -> Result<Response, ContractError> {
    // 1. Verify the proof that the decryption is valid.
    // 2. Store the tally
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    match msg {
        QueryMsg::GetPoll {} => to_binary(&query_poll(deps, env, msg)?)
    }
}

fn query_poll(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<PollResponse> {
    Ok(PollResponse {
        poll_details: POLL.load(deps.storage).unwrap(),
        total_votes: TOTAL_VOTES.load(deps.storage).unwrap_or_default(),
        poll_public_key: POLL_PUB_KEY.load(deps.storage).unwrap(),
        encrypted_tally: ENCRYPTED_VOTE.load(deps.storage).unwrap()
    })
}

#[cfg(test)]
mod tests {

    use elastic_elgamal::{group::Ristretto, PublicKey, Keypair, app::ChoiceParams, app::{EncryptedChoice, SingleChoice}, CandidateDecryption, DiscreteLogTable, SecretKey, Ciphertext};
    use rand::{thread_rng, rngs::ThreadRng};
    use cosmwasm_std::{testing::{
        mock_dependencies, mock_env, mock_info, MockQuerier, MOCK_CONTRACT_ADDR, MockStorage, MockApi,
    }, from_binary, Deps, MessageInfo, OwnedDeps, Empty};

    use crate::{msg::{InstantiateMsg, ExecuteMsg, Poll, PollType, Vote, QueryMsg, PollResponse}, helpers::{to_base64, serialize_encrypted_vote, deserialize_encrypted_vote}};

    use super::{instantiate, execute, query};
    /// let mut rng = thread_rng();
/// 
/// 
    fn vote(choice_params: ChoiceParams<Ristretto, SingleChoice>, choice: usize, rng: &mut ThreadRng, deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>, info: MessageInfo) -> PollResponse {
        let enc = EncryptedChoice::single(&choice_params, choice, rng);
        let vote1 = ExecuteMsg::AddVote {
            vote: Vote {
            ciphertexts: serialize_encrypted_vote(enc.choices_unchecked().to_vec()),
            range_proof: to_base64(enc.range_proof().to_bytes()),
            sum_proof: to_base64(enc.sum_proof().to_bytes())
            }
        };
        let res = execute(deps.as_mut(), mock_env(), info, vote1).unwrap();

        // Query,  decrypt and check
        let q = QueryMsg::GetPoll {  };
        let res = query(deps.as_ref(), mock_env(), q.clone()).unwrap();
        let poll_response = from_binary::<PollResponse>(&res).unwrap();
        poll_response
    }

    fn check_vote(sk: SecretKey<Ristretto>, enc_votes: Vec<Ciphertext<Ristretto>>, lookup_table: DiscreteLogTable<Ristretto>, votes0: u64, votes1: u64, votes2: u64) {
        for (index, value) in enc_votes.iter().enumerate() {
            let votes = sk.decrypt(*value, &lookup_table).unwrap();
            println!("Vote: {} {}", index, votes);
            match index {
               0 => assert_eq!(votes, votes0),
               1 => assert_eq!(votes, votes1),
               2 => assert_eq!(votes, votes2),
               _ => ()
            };
        }
    }

    #[test]
    fn test_flow() {
        let mut deps = mock_dependencies();
        let creator = String::from("creator");
        let info = mock_info(&creator, &[]);
        // Generate Key
        let mut rng = thread_rng();
        let lookup_table = DiscreteLogTable::<Ristretto>::new(0..5);
        let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();

        // Instantiate
        let inst = InstantiateMsg {
            poll_public_key: to_base64(pk.as_bytes().to_vec())
        };
        
        instantiate(deps.as_mut(), mock_env(), info.clone(), inst);

        // Setup Poll
        let setup = ExecuteMsg::SetupPoll { 
            poll_details: Poll {
                topic: String::from("Yes or No or Don't no"),
                choices: vec![String::from("Yes"), String::from("No"), String::from("Don't no")],
                poll_type: PollType::SingleChoice,
                start_time: 0,
                end_time: 1
            }
        };
        let res = execute(deps.as_mut(), mock_env(), info.clone(), setup).unwrap();
        // Add Vote1
        let choice_params = ChoiceParams::single(pk, 3);
        ///
        let mut poll_response = vote(choice_params.clone(), 2, &mut rng, &mut deps, info.clone());
        let mut enc_votes = deserialize_encrypted_vote(poll_response.encrypted_tally);
        check_vote(sk.clone(), enc_votes, lookup_table.clone(), 0, 0, 1);
        

        // Add Vote2
        poll_response = vote(choice_params.clone(), 0, &mut rng, &mut deps, info.clone());
        let enc_votes = deserialize_encrypted_vote(poll_response.encrypted_tally);
        check_vote(sk.clone(), enc_votes, lookup_table.clone(), 1, 0, 1);


        // Add Vote3
        poll_response = vote(choice_params.clone(), 0, &mut rng, &mut deps, info.clone());
        let enc_votes = deserialize_encrypted_vote(poll_response.encrypted_tally);
        check_vote(sk.clone(), enc_votes, lookup_table.clone(), 2, 0, 1);

        // Add Vote4
        poll_response = vote(choice_params.clone(), 1, &mut rng, &mut deps, info.clone());
        let enc_votes = deserialize_encrypted_vote(poll_response.encrypted_tally);
        check_vote(sk.clone(), enc_votes, lookup_table.clone(), 2, 1, 1);

        
    }
}
