use crate::mc::{
    BoundedStr, FieldRead, FieldWrite, Result,
};

/// Authentication/Game profile property (name, value, optional signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property<'a> {
    pub name: BoundedStr<'a, 32767>,
    pub value: BoundedStr<'a, 32767>,
    pub signature: Option<BoundedStr<'a, 32767>>,
}

impl<'a> FieldRead<'a> for Property<'a> {
    fn read_field(input: &mut &'a [u8]) -> Result<Self> {
        let name = BoundedStr::read_field(input)?;
        let value = BoundedStr::read_field(input)?;
        let signature = if input.is_empty() || input[0] == 0 {
            if !input.is_empty() {
                *input = &input[1..];
            }
            None
        } else {
            *input = &input[1..];
            Some(BoundedStr::read_field(input)?)
        };
        Ok(Property { name, value, signature })
    }
}

impl FieldWrite for Property<'_> {
    fn write_field(&self, out: &mut Vec<u8>) -> Result<()> {
        self.name.write_field(out)?;
        self.value.write_field(out)?;
        match &self.signature {
            Some(sig) => {
                out.push(1);
                sig.write_field(out)?;
            }
            None => {
                out.push(0);
            }
        }
        Ok(())
    }
}
