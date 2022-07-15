use bitcoin::{Script, TxOut, AddressType};
use crate::psbt::{Psbt, PsbtError};
use std::convert::TryFrom;

mod error;

pub use error::RequestError;
use error::InternalRequestError;

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

pub struct UncheckedProposal {
    psbt: Psbt,
}

pub struct MaybeInputsOwned {
    psbt: Psbt,
}

pub struct MaybeScriptsSupported {
    psbt: Psbt,
}

pub struct MaybePrevoutsSeen {
    psbt: Psbt,
}
pub trait Proposal {
    fn psbt(&self) -> &bitcoin::util::psbt::PartiallySignedTransaction;
}

impl UncheckedProposal {
    pub fn from_request(body: impl std::io::Read, query: &str, headers: impl Headers) -> Result<Self, RequestError> {
        use crate::bitcoin::consensus::Decodable;

        let content_type = headers.get_header("content-type").ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
        if content_type != "text/plain" {
            return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
        }
        let content_length = headers
            .get_header("content-length")
            .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
            .parse::<u64>()
            .map_err(InternalRequestError::InvalidContentLength)?;
        // 4M block size limit with base64 encoding overhead => maximum reasonable size of content-length
        if content_length > 4_000_000 * 4 / 3 {
            return Err(InternalRequestError::ContentLengthTooLarge(content_length).into());
        }

        // enforce the limit
        let mut limited = body.take(content_length);
        let reader = base64::read::DecoderReader::new(&mut limited, base64::STANDARD);
        let psbt = bitcoin::util::psbt::PartiallySignedTransaction::consensus_decode(reader)
        .map_err(InternalRequestError::Decode)?;
        let psbt = Psbt::try_from(psbt).map_err(InternalRequestError::PsbtError)?;

        Ok(UncheckedProposal {
            psbt,
        })
    }

    /// The Sender's Original PSBT
    pub fn get_transaction_to_check_broadcast(&self) -> bitcoin::Transaction {
        self.psbt.clone().extract_tx()
    }

    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `get_transaction_to_check_broadcast()` before calling this method.
    ///
    /// Check this if you generate bitcoin uri to receive PayJoin on sender request without manual human approval, like a payment processor.
    /// Such so called "interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn attest_tested_and_scheduled_broadcast(self) -> MaybeInputsOwned {
        MaybeInputsOwned {
            psbt: self.psbt,
        }
    }

    /// Call this method if the only way to initiate a PayJoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `get_transaction_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn attest_manual_receive_endpoint(self) -> MaybeInputsOwned {
        MaybeInputsOwned {
            psbt: self.psbt,
        }
    }
}

impl MaybeInputsOwned {
    /// The receiver should not be able to sign for any of the Original PSBT's inputs.
    /// Check that none of them are owned by the receiver downstream before proceeding.
    pub fn iter_input_script_pubkeys(&self) -> impl Iterator<Item = Result<&Script, PsbtError>> {
        self.psbt.iter_funding_utxos().map(|utxo| {
            match utxo {
                Ok(utxo) => Ok(&utxo.script_pubkey),
                Err(e) => Err(e),
            }
        })
    //pub fn script_pubkeys(&self) -> impl Iterator<Item=&Script> + '_ {
    }

    /// If the sender included inputs that the receiver could sign for in the original PSBT,
    /// the receiver must either return error original-psbt-rejected or make sure they do not sign those inputs in the payjoin proposal.
    ///
    /// Call this after checking downstream.
    pub fn attest_inputs_not_owned(self) -> MaybeScriptsSupported {
        MaybeScriptsSupported {
            psbt: self.psbt,
        }
    }
}

impl MaybeScriptsSupported {
    pub fn iter_input_script_types(&self, network: bitcoin::Network) -> Vec<Option<AddressType>> {
        self.psbt.iter_funding_utxos().map(|utxo| {
            match utxo {
                Ok(utxo) => Ok(&utxo.script_pubkey),
                Err(e) => Err(e),
            }
        }).map(|script| {
            match script {
                Ok(script) => {
                    Some(bitcoin::Address::from_script(script, network)?.address_type()?)
                },
               _ => None,
            }
        })
        .collect()
    }

    /// If the sender's inputs are all from the same scriptPubKey type, the receiver must match the same type.
    /// If the receiver can't match the type, they must return error unavailable.
    ///
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends are not necessarily indicative of distinct wallet fingerprints but they can be.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn attest_scripts_are_supported(self) -> MaybePrevoutsSeen {
        MaybePrevoutsSeen {
            psbt: self.psbt,
        }
    }
}

impl MaybePrevoutsSeen {
    pub fn prevouts(&self) -> impl Iterator<Item = Result<&TxOut, PsbtError>> {
        self.psbt.iter_funding_utxos()
    }

    /// Make sure that the inputs included in the original transaction have never been seen before.
    /// - This prevents probing attacks.
    /// - This prevent reentrant payjoin, where a sender attempts to use payjoin transaction as a new original transaction for a new payjoin.
    ///
    /// Call this after checking downstream.
    pub fn attest_no_prevouts_seen_before(self) -> UnlockedProposal {
        UnlockedProposal { psbt: self.psbt }
    }
}

pub struct UnlockedProposal {
    psbt: Psbt,
}

impl UnlockedProposal {
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item=&bitcoin::OutPoint> {
        self.psbt.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    pub fn assume_locked(self) -> LockedProposal {
        LockedProposal {
            psbt: self.psbt,
        }
    }
}

impl Proposal for UnlockedProposal {
    fn psbt(&self) -> &bitcoin::util::psbt::PartiallySignedTransaction {
        &self.psbt
    }
}

/// Transaction that must be broadcasted.
#[must_use = "The transaction must be broadcasted to prevent abuse"]
pub struct MustBroadcast(pub bitcoin::Transaction);

pub struct LockedProposal {
    psbt: Psbt,
}

/*
impl Proposal {
    pub fn replace_output_script(&mut self, new_output_script: Script, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn replace_output(&mut self, new_output: TxOut, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn insert_output(&mut self, new_output: TxOut, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn expected_missing_fee_for_replaced_output(&self, output_type: OutputType) -> bitcoin::Amount {
    }
}
*/

pub struct ReceiverOptions {
    dust_limit: bitcoin::Amount,
}

pub enum BumpFeePolicy {
    FailOnInsufficient,
    SubtractOurFeeOutput,
}

pub struct NewOutputOptions {
    set_as_fee_output: bool,
    subtract_fees_from_this: bool,
}

pub mod test_util {
    use super::*;
    use std::collections::HashMap;

    pub struct MockHeaders(HashMap<String, String>);

    impl Headers for MockHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            self.0.get(key).map(|e| e.as_str())
        }
    }

    impl MockHeaders {
        pub fn from_vec(body: &[u8]) -> MockHeaders {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "text/plain".to_string());
            h.insert("content-length".to_string(), body.len().to_string());
            MockHeaders(h)
        }
    }

}

#[cfg(test)]
pub mod test {
    use super::*;

    #[cfg(test)]
    fn get_proposal_from_test_vector() -> Result<UncheckedProposal, RequestError> {
        use super::test_util::MockHeaders;

        // OriginalPSBT Test Vector from BIP
        // | InputScriptType | Orginal PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
        // |-----------------|-----------------------|------------------------------|-------------------------|
        // | P2SH-P2WPKH     |  2 sat/vbyte          | 0.00000182                   | 0                       |
        let original_psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

        let body = original_psbt.as_bytes();
        let headers =  MockHeaders::from_vec(body);
        UncheckedProposal::from_request(body, "", headers)
    }

    #[test]
    fn can_get_proposal_from_request() {
        let proposal = get_proposal_from_test_vector();
        assert!(proposal.is_ok(), "OriginalPSBT should be a valid request");
    }

    #[test]
    fn can_get_script_pubkeys() {
        let proposal = get_proposal_from_test_vector().unwrap()
        .attest_tested_and_scheduled_broadcast();
        let script = proposal.iter_input_script_pubkeys().next().unwrap().unwrap();
        assert!(bitcoin::Address::from_script(script, bitcoin::Network::Bitcoin)
            .unwrap()
            .address_type() == Some(AddressType::P2sh));
    }

    #[test]
    fn unchecked_proposal_unlocks_after_checks() {
        let proposal = get_proposal_from_test_vector().unwrap();
        let unlocked = proposal
            .attest_tested_and_scheduled_broadcast()
            .attest_inputs_not_owned()
            .attest_scripts_are_supported()
            .attest_no_prevouts_seen_before();
    }
}
