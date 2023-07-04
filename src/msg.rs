use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub enum PollType {
    SingleChoice,
    MultiChoice
}

#[cw_serde]
pub struct Poll {
    pub topic: String,
    pub choices: Vec<String>,
    pub poll_type: PollType,
    pub start_time: u32,
    pub end_time: u32
}

#[cw_serde]
pub struct PollTally {
    tally: Vec<u32>,
    proof: String
}

#[cw_serde]
pub struct Vote {
    pub ciphertexts: Vec<Vec<String>>,
    pub range_proof: String,
    pub sum_proof: String
}

#[cw_serde]
pub struct Decryption {
    pub verifiable_decryptions: Vec<String>,
    pub proofs: Vec<String>
}

#[cw_serde]
pub struct InstantiateMsg {
    pub poll_public_key: String 
}

#[cw_serde]
pub enum ExecuteMsg {
    SetupPoll {
        poll_details: Poll
    },
    AddVote {
        vote: Vote
    },
    DecryptTally {
        decryption: Decryption
    }
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(PollResponse)]
    GetPoll {
    }
}

#[cw_serde]
pub struct PollResponse {
    pub poll_details: Poll,
    pub total_votes: u32,
    pub poll_public_key: String,
    pub encrypted_tally: Vec<Vec<String>>,
    pub decrypted_tally: Vec<u64>
}
