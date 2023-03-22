// Disable snake case warnings for this file
#![allow(non_snake_case)]
use crypto_bigint::{U256, U128, U192};
mod camelia;
use camelia::*;

fn main() {

	// let test_key = U256::from(0x01234_5678_9abc_deff_edcb_a987_6543_2100_0112_2334_4556_6778_899a_abbc_cdde_eff);
	let test_key_256 = U256::from_be_hex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
	let test_key_128:u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;

	// let mut keychain = Keychain::new(Keysize::_256(test_key_256));
	let mut keychain = Keychain::new(Keysize::_128(test_key_128));
	keychain.key_schedule();
	println!("Keychain: {:#?}", keychain);

}
