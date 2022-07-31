
#[cfg(all(feature = "sender", feature = "receiver"))]
mod integration {
    use bitcoind::bitcoincore_rpc::RpcApi;
    use bitcoind::bitcoincore_rpc;
    use bitcoin::{Amount, Witness, hashes::hex::ToHex, TxIn, TxOut, Transaction, OutPoint, Script, psbt::Input};
    use bip78::{Uri, UriExt, PjUriExt, receiver::Proposal};
    use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
    use log::{debug, log_enabled, Level};
    use std::{collections::HashMap, str::FromStr};

    use bip78::receiver::test_util::MockHeaders;

    #[test]
    fn integration_test() {
        let _ = env_logger::try_init();
        let bitcoind_exe = std::env::var("BITCOIND_EXE")
            .ok()
            .or_else(|| bitcoind::downloaded_exe_path().ok())
            .expect("version feature or env BITCOIND_EXE is required for tests");
        let mut conf = bitcoind::Conf::default();
        conf.view_stdout = log_enabled!(Level::Debug);
        let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf).unwrap();
        let receiver = bitcoind.create_wallet("receiver").unwrap();
        let receiver_address = receiver.get_new_address(None, None).unwrap();
        let sender = bitcoind.create_wallet("sender").unwrap();
        let sender_address = sender.get_new_address(None, None).unwrap();
        bitcoind.client.generate_to_address(1, &receiver_address).unwrap();
        bitcoind.client.generate_to_address(101, &sender_address).unwrap();

        assert_eq!(
            Amount::from_btc(50.0).unwrap(),
            receiver.get_balances().unwrap().mine.trusted,
            "receiver doesn't own bitcoin"
        );

        assert_eq!(
            Amount::from_btc(50.0).unwrap(),
            sender.get_balances().unwrap().mine.trusted,
            "sender doesn't own bitcoin"
        );

        // *****************************************
        // Receiver creates the payjoin URI
        let pj_receiver_address = receiver.get_new_address(None, None).unwrap();
        let amount = Amount::from_btc(1.0).unwrap();
        let pj_uri_string = format!("{}?amount={}&pj=https://example.com", pj_receiver_address.to_qr_uri(), amount.as_btc());
        let pj_uri = Uri::from_str(&pj_uri_string).unwrap();
        let pj_uri = pj_uri.check_pj_supported().expect("Bad Uri");


        // ******************************************
        // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(pj_uri.address.to_string(), pj_uri.amount.unwrap());
        debug!("outputs: {:?}", outputs);
        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(true),
            fee_rate: Some(bip78::bitcoin::Amount::from_sat(2000)),
            ..Default::default()
        };
        let psbt = sender.wallet_create_funded_psbt(
            &[], // inputs
            &outputs,
            None, // locktime
            Some(options),
            None,
        ).expect("failed to create PSBT").psbt;
        let psbt = sender
            .wallet_process_psbt(&psbt, None, None, None)
            .unwrap()
            .psbt;
        let psbt = load_psbt_from_base64(psbt.as_bytes()).unwrap();
        debug!("Original psbt: {:#?}", psbt);
        let pj_params = bip78::sender::Params::with_fee_contribution(bip78::bitcoin::Amount::from_sat(10000), None);
        let (req, ctx) = pj_uri.create_pj_request(psbt, pj_params).unwrap();
        let headers = MockHeaders::from_vec(&req.body);

        // **************************
        // Receiver receive payjoin proposal, IRL it will be an HTTP request (over ssl or onion)
        let proposal = bip78::receiver::UncheckedProposal::from_request(req.body.as_slice(), "", headers).unwrap();
        
        // Receive Check 1: Is Broadcastable
        let original_tx = proposal.get_transaction_to_check_broadcast();
        let tx_is_broadcastable = bitcoind.client.test_mempool_accept(&[bitcoin::consensus::encode::serialize(&original_tx).to_hex()]).unwrap().first().unwrap().allowed;
        assert!(tx_is_broadcastable);
        
        // TODO Receive Check 2, 3, 4, Other OriginalPSBT Checks

        let unlocked = proposal.attest_tested_and_scheduled_broadcast();

        // Select receiver payjoin inputs. Lock them.
        let receiver_coins = receiver.list_unspent(None, None, None, Some(false), None).unwrap();
        let receiver_coin = receiver_coins.first().unwrap();
        // TODO Select to avoid Unecessary Input and other Heuristics.
        // This Gist <https://gist.github.com/AdamISZ/4551b947789d3216bacfcb7af25e029e> explains how

        // TODO In a payment processor, this is where one would defend against the failure case
        // I'm not sure if we can take a callback as a param or we have to assume downstream does the check
        // let scheduled = proposal.assume_original_broadcast_has_been_scheduled();

        //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt, 
        //      TODO add sender additionalfee to our output
        let receiver_input = Input {
            witness_utxo: Some(TxOut {
               
                value: receiver_coin.amount.as_sat(),
                script_pubkey: receiver_coin.script_pub_key.to_owned(),
            }),
             // + redeem_script = Script::new_v0_p2wpkh
            // + bip32_derivation
            // + sighash_type
            ..Default::default() };

        // Create new payjoin_psbt from original Tx as in example Creator.
        let unsigned_original_tx = Transaction {
            version: 2,
            lock_time: 0,
            // TODO create via loop in helper function in receiver
            input: vec! [
                TxIn {
                    previous_output: original_tx.input.first().unwrap().previous_output,
                    ..Default::default()
                }
            ],
            output: original_tx.output,
        };
        let mut payjoin_psbt = Psbt::from_unsigned_tx(unsigned_original_tx).unwrap();
        
        // for mut input in payjoin_psbt.inputs {
        //     input = Input {
        //         witness_utxo: input.witness_utxo,
        //         ..Default::default()
        //     };

        //     // input.redeem_script =
        //     // input.bip32_derivation =
        //     // input.sighash_type = 
        // }

        // Update payjoin_psbt
        //      add receiver input utxo
        payjoin_psbt.unsigned_tx.input.push({
            TxIn {
                previous_output: OutPoint { txid: receiver_coin.txid, vout: receiver_coin.vout },
                ..Default::default()
            }
        });
        //      add receiver input redeemScripts, witnessScripts, derivation to map
        payjoin_psbt.inputs.push(receiver_input);

        //      increase receiver output value in proportion to receiver controbution
        payjoin_psbt.unsigned_tx.output[0].value += receiver_coin.amount.as_sat();
// --------------------- above looks good
        //      identify receiver payment output to increase by our input amount
        //      TODO identify sender fee output if one exists
        // let minRelayFeeRate =

        // TODO if additionalfee > Amount::ZERO { receiver, take it }
        //      add new_change, new_change.amount = original_psbt change's + receiver_inputs.amount() - sender additionalfees

        // TODO Sign payjoin psbt
        //println!("{:?}", &payjoin_tx);
        let payjoin_psbt = receiver
        .wallet_process_psbt(&payjoin_psbt.to_string(), None, None, None)
        .unwrap()
        .psbt;
        let payjoin_psbt = load_psbt_from_base64(payjoin_psbt.as_bytes()).unwrap();
        debug!("Receiver's PayJoin PSBT: {:#?}", payjoin_psbt);

        // return it to sender via http response *in your imagination*

        // **********************
        // Sender [TODO checks] signs, finalizes, extracts, and broadcasts
        let payjoin_psbt = sender
        .wallet_process_psbt(&payjoin_psbt.to_string(), None, None, None)
        .unwrap()
        .psbt;
        let payjoin_psbt = load_psbt_from_base64(payjoin_psbt.as_bytes()).unwrap();
        debug!("Sender's PayJoin PSBT: {:#?}", payjoin_psbt);

        let payjoin_tx = payjoin_psbt.extract_tx();
        bitcoind.client.send_raw_transaction(&payjoin_tx).unwrap().first().unwrap();
    }

    fn load_psbt_from_base64(mut input: impl std::io::Read) -> Result<Psbt, bip78::bitcoin::consensus::encode::Error> {
        use bip78::bitcoin::consensus::Decodable;

        let reader = base64::read::DecoderReader::new(&mut input, base64::Config::new(base64::CharacterSet::Standard, true));
        Psbt::consensus_decode(reader)
    }
    
}