use failure::Fail;

#[derive(Fail, Debug)]
#[fail(display = "invalid output buffer length")]
pub struct InvalidOutputLen;
#[fail(display = )]

#[derive(Fail, Debug)]
#[fail(display = "invalid scrypt parameters")]
pub struct InvalidParams;
