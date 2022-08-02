#[derive(Debug)]
pub struct RequestError(InternalRequestError);

#[derive(Debug)]
pub(crate) enum InternalRequestError {
    Decode(bitcoin::consensus::encode::Error),
    MissingHeader(&'static str),
    InvalidContentType(String),
    InvalidContentLength(std::num::ParseIntError),
    ContentLengthTooLarge(u64),
    Psbt(crate::psbt::InconsistentPsbt),
    PsbtInputs(crate::psbt::PrevTxOutError),
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self {
        RequestError(value)
    }
}
