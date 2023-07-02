use cw_storage_plus::Item;
use elastic_elgamal::{Ciphertext, group::Ristretto};

use cosmwasm_schema::{cw_serde};
use crate::msg::{Poll};

pub const ENCRYPTED_VOTE: Item<Vec<Vec<String>>> = Item::new("encrypted_vote");
pub const DECRYPTED_TALLY: Item<Vec<i32>> = Item::new("tally");
pub const POLL: Item<Poll> = Item::new("poll");
pub const TOTAL_VOTES: Item<u32> = Item::new("total_votes");
pub const POLL_PUB_KEY: Item<String> = Item::new("poll_pub_key");
