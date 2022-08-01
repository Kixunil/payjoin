use std::fmt;

use crate::fee_rate::FeeRate;

pub(crate) struct Params {
    // version
    // v: usize,
    // disableoutputsubstitution
    pub disable_output_substitution: bool,
    // maxadditionalfeecontribution, additionalfeeoutputindex
    pub additional_fee_contribution: Option<(bitcoin::Amount, usize)>,
    // minfeerate
    pub min_feerate: FeeRate,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            disable_output_substitution: false,
            additional_fee_contribution: None,
            min_feerate: FeeRate::ZERO,
        }
    }
}

impl Params {
    #[cfg(feature = "receiver")]
    pub fn parse(query: &str) -> Result<Params, ParamsError> {

        let mut params = Params::default();

        let mut additional_fee_output_index = None;
        let mut max_additional_fee_contribution = None;

        let query =  url::Url::parse(query).ok();
        if let Some(query) = query {
            for (k, v) in query.query_pairs().into_owned() {
                match (k.as_str(), v) {
                    ("v", v) => if v != "1" {
                        return Err(ParamsError::UnknownVersion)
                    },
                    ("additionalfeeoutputindex", index) =>  {
                        if let Ok(index) = index.parse::<usize>() {
                            // Check for index out of bounds at fee application.
                            // Params doesn't need to know about psbt.
                            additional_fee_output_index = Some(index);
                        }
                    },
                    ("maxadditionalfeecontribution", fee) => {
                        max_additional_fee_contribution = bitcoin::Amount::from_str_in(&fee, bitcoin::Denomination::Bitcoin).ok();
                    }
                    ("minfeerate", feerate) => {
                        if let Ok(rate) = feerate.parse::<u64>() {
                            params.min_feerate = FeeRate::from_sat_per_vb(rate);
                        }
                    }
                    ("disableoutputsubstitution", _) => params.disable_output_substitution = true, // existance is truthy
                    _ => (),
                }
            }
        }
        if let (Some(amount), Some(index)) = (max_additional_fee_contribution, additional_fee_output_index) {
            params.additional_fee_contribution = Some((amount, index));
        }

        Ok(params)
    }
}

#[derive(Debug)]
pub(crate) enum ParamsError {
    UnknownVersion,
}

impl fmt::Display for ParamsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParamsError::UnknownVersion => write!(f, "unknown version"),
        }
    }
}

impl std::error::Error for ParamsError {}
