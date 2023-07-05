**store wasm:**

```
   ./main  tx  wasm store  ../cw-poll/target/wasm32-unknown-unknown/release/cw_poll.wasm  --from account-1 -t --chain-id chain-dev --home ./build/nodedev  --gas-prices 381000000nhash --gas "4000000"
```
**instantiate**

```
  ./main tx wasm instantiate  7 '{"poll_public_key": "MC6xp3UbtRrh9Chf_9JsjbmzUqjyvPz3EIoq82YMVTo"}' --from account-1 -t --chain-id chain-dev --home ./build/nodedev --gas-prices 381000000nhash --gas "4000000"  --label "test" --no-admin
```

**setup_poll**

```
  ./main tx wasm  execute tp1aaf9r6s7nxhysuegqrxv0wpm27ypyv4886medd3mrkrw6t4yfcnsdghht4 '{"setup_poll": {"poll_details": {"topic": "Yes - No - May be", "choices": ["0", "1", "2", "3", "4"], "poll_type": "single_choice", "start_time": 1, "end_time": 2}}}' --from account-1 -t --chain-id chain-dev --home ./build/nodedev --gas-prices 381000000nhash --gas "4000000"
```

**add_vote**

```
  ./main tx wasm execute tp1aaf9r6s7nxhysuegqrxv0wpm27ypyv4886medd3mrkrw6t4yfcnsdghht4 '{"add_vote":{"vote":{"ciphertexts":[["uOlsaptzwigFT52F15Kfct09uO2IHqPlGUy8vSxj0mg","Xv3UHUfouyVRVQbcmJT-wyXYosRjZStDEB2dqgEuRFY"],["JplqqoR7Uyf9mE5ukLXhVYV49ERnn9bPw6hoWopZk1A","fuUT5buugaIg3ivpkNmuB7vIR1gVArvVfJ1g1FwrJXI"],["xk-BRdPU4gHI-EcUtpo66mcWRen9pJ7dLZcYRi_FCRo","0AaWAn-w52TOyhYrLH1XeFvLZPfuKgjC_Wdn_LU1C1E"],["0uBVWCAsqk6F8MWFVAxY45litAOWnCWAG2wTdAFMGik","loOs2tOzwfl_trNXr4C_8y9Cbexdar-z4KtE-ylOezo"],["APYKOKxydm1V0h2eSRiT-1jCSkfgN_lDtfQa7XYCbDs","_BnpRODtkEQTJayX6hu_BYfzGr7lt78m8Sk1vVd_kUY"]],"range_proof":"dfyTb0PjmGDE_LEVAluN-hLvo18scHBAPg9xA78ZkAlnOIbBGfi5vf0V6kV_zh-XLEtGRQ5O4UGRDyzFNXNFCMx4imYBiYGnInq4fyS10MNA9rgNGvNGC_NJLS9MaoAK76g_7vHvJadBnUwIkEDbtg4C40ovWJo6h9VZaEC6IA3Zilj3pQu7dMEWPBfqPrBUYQmqP2UzjSS-mWsUkYGfCPj2Z7tzkRGCd0KgTDYQIvFRZSevcekyDt9eV3OVMVwF_jc7fsh3kM_ehkR_4AGM3Hsc8JxzbhQpXnEhOVh0hAswjWE3GxtubXhsxPRse_T16TF7TmgowOj2N6nbdhxHAM3fOSIDY5ciWPDS6gbsULHPEBHo-C7Xh87Q9VkPiIgBxJG7BlKza3d3T2LcnjZBrDK43SvISDMKXoiP4KaaWQ4P_KvoYHqd08SqeZrnW_rKF6WQTHySzd7rOY-jE9P-CA","sum_proof":"zQC0vE2LbwXnq0CqPCM23N4oBQJCU2cAaFcKsW-Z8Qa8KZabJUbpY32g82QHTk4aGxVyWfBNUtcOMI2VdrwwBg"}}}'  --from account-1 -t --chain-id chain-dev --home ./build/nodedev --gas-prices 381000000nhash --gas "4000000"
```

**decryption**

```
  ./main tx wasm execute tp1aaf9r6s7nxhysuegqrxv0wpm27ypyv4886medd3mrkrw6t4yfcnsdghht4 '{"decrypt_tally": { "decryption": {"verifiable_decryptions":["Xv3UHUfouyVRVQbcmJT-wyXYosRjZStDEB2dqgEuRFY","nDgKcETZyB5BxhsdAX3ehhmSMGe0OTHVPgBHL-VNIGs","0AaWAn-w52TOyhYrLH1XeFvLZPfuKgjC_Wdn_LU1C1E","loOs2tOzwfl_trNXr4C_8y9Cbexdar-z4KtE-ylOezo","_BnpRODtkEQTJayX6hu_BYfzGr7lt78m8Sk1vVd_kUY"],"proofs":["VSaY1PNOne--R_lvN2ZcHCJT-i3UeG3jANgo_ZwYwQZwUxCSvq-pTz97ptJbdiEx9NgDPAY5Bi63aLRIPltjBQ","qbe2DMNdaWHaw4ALPj3tHhiKp9h0KrovXwnTmGtkog0Z33-D6V23aXyZ9NJL0jT6fRwJF19_1MH5rxFZrkkSBg","MYmbNpV8fDKK7gKzZ2HgewZ4_iGV5pSCFTG9yHV25w24k_hsqfKglq95hdkHg0yMpEEe_sKz164hGM6-AjZyCA","JoUcsrn5P6t9ez1StE4bqoKKZ_zpcvuFKIpkzCx5Tg9P4Tx2i-Y7DDdZ8J4kJ7eOZkeE3H3dJHlO90L52qnSCQ","eEN0hG9cdiyyzoJim-nwSLrcAWtlQ3Ia9jkY138YIAmn1RkPN8EeGn8cDglA4tJiJiNP6-EpOlztW9-UnnZBCQ"]}}}' --from account-1 -t --chain-id chain-dev --home ./build/nodedev --gas-prices 381000000nhash --gas "4000000"
```

**query**

```
  ./main query wasm contract-state smart tp1aaf9r6s7nxhysuegqrxv0wpm27ypyv4886medd3mrkrw6t4yfcnsdghht4 '{"get_poll": {}}'  -t
```