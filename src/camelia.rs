use std::ops::Shr;

use crypto_bigint::{U256, U192, Checked};

#[derive(Debug)]
pub enum Keysize {
	_128(u128),
	_192(U192),
	_256(U256),
}

#[derive(Debug)]
pub struct Keychain {
	secret_key: Keysize,
	kl: [u64; 6],  // Logic transformation sub-keys
	k : [u64; 24], // Feistel round sub-keys
	kw: [u64; 4],  // Whitening sub-keys
	KA: u128, 	   // Key Scheduler result A
	KB: u128, 	   // Key Scheduler result B
	// Intermediate resulta
	scheduler_KL: u128, // Unmodifiec scheduler secret key, left half
	scheduler_KR: u128, // Unmodifiec scheduler secret key, right half
	scheduler_input: u128, // Scheduler XORed secret key
}

impl Keychain {
	pub fn new(secret_key: Keysize) -> Self {
		Self {
			secret_key,
			kl: [0; 6],
			k : [0; 24],
			kw: [0; 4],
			KA: 0,
			KB: 0,
			scheduler_KL: 0,
			scheduler_KR: 0,
			scheduler_input: 0,
		}
	}
	pub fn key_schedule(&mut self) {

		// Constant sigma-values
		const SIGMA: [u64; 6] = [
			0xA09E667F_3BCC908B,
			0xB67AE858_4CAA73B2,
			0xC6EF372F_E94F82BE,
			0x54FF53A5_F1D36F1C,
			0x10E527FA_DE682D1D,
			0xB05688C2_B3E6C1FD,
		];

		// Half-keys, summing up to a 256-bit key
		let key_L: u128 = match self.secret_key {
			Keysize::_128(key) => key as u128, // Whole key
			Keysize::_192(key) => u128::from(key.shr(64).resize()), // Get first 128 bits
			Keysize::_256(key) => u128::from(key.split().0), // Split and only use first 128 bits
		}; self.scheduler_KL = key_L; // Saving key

		let key_R: u128 = match self.secret_key {
			Keysize::_128(_  ) => 0u128, // Zeroed key
			Keysize::_192(key) => todo!(), // Get first 128 bits (could't figure it our rn)
			Keysize::_256(key) => u128::from(key.split().1), // Split and only use first 128 bits
		}; self.scheduler_KR = key_R; // Saving key

		// First, right and left get XORed
		let mut scheduler_input = key_L ^ key_R;
		self.scheduler_input = scheduler_input; // Saving key

		let mut sched_left = (scheduler_input >> 64) as u64;
		let mut sched_right = scheduler_input as u64;

		// Then, the key is "encrypted" with two rounds using SIGMA1 and SIGMA2
		(sched_left, sched_right) = feistel_round( sched_left , sched_right, SIGMA[0] );
		(sched_left, sched_right) = feistel_round( sched_left , sched_right, SIGMA[1] );

		// The result is joined, and XORed with key_L and encrypted again with two rounds
		scheduler_input = u128::from(sched_left) << 64 | u128::from(sched_right);
		scheduler_input ^= key_L;

		sched_left = (scheduler_input >> 64) as u64;
		sched_right = scheduler_input as u64;

		(sched_left, sched_right) = feistel_round( sched_left , sched_right, SIGMA[2] );
		(sched_left, sched_right) = feistel_round( sched_left , sched_right, SIGMA[3] );

		// This result is now KA
		self.KA = u128::from(sched_left) << 64 | u128::from(sched_right);

		if let Keysize::_256(_) = self.secret_key {
			// If the key is 256 bits, the key is encrypted again with two rounds using SIGMA3 and SIGMA4
			scheduler_input = self.KA ^ key_R;
			sched_left = (scheduler_input >> 64) as u64;
			sched_right = scheduler_input as u64;

			(sched_left, sched_right) = feistel_round( sched_left , sched_right, SIGMA[4] );
			(sched_left, sched_right) = feistel_round( sched_left , sched_right, SIGMA[5] );

			// This result is now KB
			self.KB = u128::from(sched_left) << 64 | u128::from(sched_right);
		} else {
			// If the key is 128 or 192 bits, whe zero KB
			// Even though we don't use it for 128 bits
			self.KB = 0u128;
		}

		// Sub-key generation using specification tables
		match self.secret_key {
			Keysize::_128(_) => {
				/* Whitening Keys */
				(self.kw[0], self.kw[1]) = split_64(self.scheduler_KL);
				(self.kw[2], self.kw[3]) = split_64(self.KA.rotate_left(111));

				/* Logic transformation keys */
				(self.kl[0], self.kl[1]) = split_64(self.KA.rotate_left(30));
				(self.kl[2], self.kl[3]) = split_64(self.scheduler_KL.rotate_left(77));

				/* Feistel round keys */
				(self.k[0], self.k[1]) = split_64(self.KA.rotate_left(0));
				(self.k[2], self.k[3]) = split_64(self.scheduler_KL.rotate_left(15));
				(self.k[4], self.k[5]) = split_64(self.KA.rotate_left(15));
				(self.k[6], self.k[7]) = split_64(self.scheduler_KL.rotate_left(45));
				self.k[8] = split_64(self.KA.rotate_left(45)).0;
				self.k[9] = split_64(self.scheduler_KL.rotate_left(60)).1;
				(self.k[10], self.k[11]) = split_64(self.KA.rotate_left(60));
				(self.k[12], self.k[13]) = split_64(self.scheduler_KL.rotate_left(94));
				(self.k[14], self.k[15]) = split_64(self.KA.rotate_left(94));
				(self.k[16], self.k[17]) = split_64(self.scheduler_KL.rotate_left(111));
			},
			_ => {
				/* Whitening Keys */
				(self.kw[0], self.kw[1]) = split_64(self.scheduler_KL);
				(self.kw[2], self.kw[3]) = split_64(self.KB.rotate_left(111));

				/* Logic transformation keys */
				(self.kl[0], self.kl[1]) = split_64(self.scheduler_KR.rotate_left(30));
				(self.kl[2], self.kl[3]) = split_64(self.scheduler_KL.rotate_left(60));
				(self.kl[4], self.kl[5]) = split_64(self.KA.rotate_left(77));

				/* Feistel round keys */
				(self.k[0], self.k[1]) = split_64(self.KB.rotate_left(0));
				(self.k[2], self.k[3]) = split_64(self.scheduler_KR.rotate_left(15));
				(self.k[4], self.k[5]) = split_64(self.KA.rotate_left(15));
				(self.k[6], self.k[7]) = split_64(self.KB.rotate_left(30));
				(self.k[8], self.k[9]) = split_64(self.scheduler_KL.rotate_left(45));
				(self.k[10], self.k[11]) = split_64(self.KA.rotate_left(45));
				(self.k[12], self.k[13]) = split_64(self.scheduler_KR.rotate_left(60));
				(self.k[14], self.k[15]) = split_64(self.KB.rotate_left(60));
				(self.k[16], self.k[17]) = split_64(self.scheduler_KL.rotate_left(77));
				(self.k[18], self.k[19]) = split_64(self.scheduler_KR.rotate_left(94));
				(self.k[20], self.k[21]) = split_64(self.KA.rotate_left(94));
				(self.k[22], self.k[23]) = split_64(self.scheduler_KL.rotate_left(111));
			},
		}
	}
}

// 
/**
 * A simple round of a feistel network, denoting the equations
 * L_i+1 = R xor F(L, K_i)
 * R_i+1 = L
 */
fn feistel_round( input_left: u64, input_right: u64, key: u64 ) -> (u64, u64) {
	( input_right ^ cypher_function(input_left, key), input_left )
}

// Camellia's F-Function
fn cypher_function( input: u64, key: u64 ) -> u64 {
	permutation_function( substitution_function( input ^ key ))
}

// Realiza compuertas XOR entre los bits de entrada en distinto orden, para realizar una permutación
fn permutation_function( input: u64 ) -> u64 {
	
	let mut in_bytes: [u8; 8] = input.to_be_bytes();

	// Permutamos los bits de entrada
	in_bytes[0] = in_bytes[0] ^ in_bytes[2] ^ in_bytes[3] ^ in_bytes[5] ^ in_bytes[6] ^ in_bytes[7];
	in_bytes[1] = in_bytes[0] ^ in_bytes[1] ^ in_bytes[3] ^ in_bytes[4] ^ in_bytes[6] ^ in_bytes[7];
	in_bytes[2] = in_bytes[0] ^ in_bytes[1] ^ in_bytes[2] ^ in_bytes[4] ^ in_bytes[5] ^ in_bytes[7];
	in_bytes[3] = in_bytes[1] ^ in_bytes[2] ^ in_bytes[3] ^ in_bytes[4] ^ in_bytes[5] ^ in_bytes[6];
	in_bytes[4] = in_bytes[0] ^ in_bytes[1] ^ in_bytes[5] ^ in_bytes[6] ^ in_bytes[7];
	in_bytes[5] = in_bytes[1] ^ in_bytes[2] ^ in_bytes[4] ^ in_bytes[6] ^ in_bytes[7];
	in_bytes[6] = in_bytes[2] ^ in_bytes[3] ^ in_bytes[4] ^ in_bytes[5] ^ in_bytes[7];
	in_bytes[7] = in_bytes[0] ^ in_bytes[3] ^ in_bytes[4] ^ in_bytes[5] ^ in_bytes[6];

	u64::from_be_bytes(in_bytes)

}

// Utiliza las cajas-s para reemplazar los bits de entrada
fn substitution_function( input: u64 ) -> u64 {
	
	const SBOX1: [u8; 256] = [
		112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
		35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
		134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
		166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
		139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
		223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
		20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
		254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
		170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
		16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
		135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
		82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
		233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
		120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
		114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
		64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158
	];

	const SBOX2: [u8; 256] = [
		224, 5, 88, 217, 103, 78, 129, 203, 201, 11, 174, 106, 213, 24, 93, 130,
		70, 223, 214, 39, 138, 50, 75, 66, 219, 28, 158, 156, 58, 202, 37, 123,
		13, 113, 95, 31, 248, 215, 62, 157, 124, 96, 185, 190, 188, 139, 22, 52,
		77, 195, 114, 149, 171, 142, 186, 122, 179, 2, 180, 173, 162, 172, 216, 154,
		23, 26, 53, 204, 247, 153, 97, 90, 232, 36, 86, 64, 225, 99, 9, 51,
		191, 152, 151, 133, 104, 252, 236, 10, 218, 111, 83, 98, 163, 46, 8, 175,
		40, 176, 116, 194, 189, 54, 34, 56, 100, 30, 57, 44, 166, 48, 229, 68,
		253, 136, 159, 101, 135, 107, 244, 35, 72, 16, 209, 81, 192, 249, 210, 160,
		85, 161, 65, 250, 67, 19, 196, 47, 168, 182, 60, 43, 193, 255, 200, 165,
		32, 137, 0, 144, 71, 239, 234, 183, 21, 6, 205, 181, 18, 126, 187, 41,
		15, 184, 7, 4, 155, 148, 33, 102, 230, 206, 237, 231, 59, 254, 127, 197,
		164, 55, 177, 76, 145, 110, 141, 118, 3, 45, 222, 150, 38, 125, 198, 92,
		211, 242, 79, 25, 63, 220, 121, 29, 82, 235, 243, 109, 94, 251, 105, 178,
		240, 49, 12, 212, 207, 140, 226, 117, 169, 74, 87, 132, 17, 69, 27, 245,
		228, 14, 115, 170, 241, 221, 89, 20, 108, 146, 84, 208, 120, 112, 227, 73,
		128, 80, 167, 246, 119, 147, 134, 131, 42, 199, 91, 233, 238, 143, 1, 61
	];

	const SBOX3: [u8; 256] = [
		56, 65, 22, 118, 217, 147, 96, 242, 114, 194, 171, 154, 117, 6, 87, 160,
		145, 247, 181, 201, 162, 140, 210, 144, 246, 7, 167, 39, 142, 178, 73, 222,
		67, 92, 215, 199, 62, 245, 143, 103, 31, 24, 110, 175, 47, 226, 133, 13,
		83, 240, 156, 101, 234, 163, 174, 158, 236, 128, 45, 107, 168, 43, 54, 166,
		197, 134, 77, 51, 253, 102, 88, 150, 58, 9, 149, 16, 120, 216, 66, 204,
		239, 38, 229, 97, 26, 63, 59, 130, 182, 219, 212, 152, 232, 139, 2, 235,
		10, 44, 29, 176, 111, 141, 136, 14, 25, 135, 78, 11, 169, 12, 121, 17,
		127, 34, 231, 89, 225, 218, 61, 200, 18, 4, 116, 84, 48, 126, 180, 40,
		85, 104, 80, 190, 208, 196, 49, 203, 42, 173, 15, 202, 112, 255, 50, 105,
		8, 98, 0, 36, 209, 251, 186, 237, 69, 129, 115, 109, 132, 159, 238, 74,
		195, 46, 193, 1, 230, 37, 72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
		41, 205, 108, 19, 100, 155, 99, 157, 192, 75, 183, 165, 137, 95, 177, 23,
		244, 188, 211, 70, 207, 55, 94, 71, 148, 250, 252, 91, 151, 254, 90, 172,
		60, 76, 3, 53, 243, 35, 184, 93, 106, 146, 213, 33, 68, 81, 198, 125,
		57, 131, 220, 170, 124, 119, 86, 5, 27, 164, 21, 52, 30, 28, 248, 82,
		32, 20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227, 64, 79
	];

	const SBOX4: [u8; 256] = [
		112, 44, 179, 192, 228, 87, 234, 174, 35, 107, 69, 165, 237, 79, 29, 146,
		134, 175, 124, 31, 62, 220, 94, 11, 166, 57, 213, 93, 217, 90, 81, 108,
		139, 154, 251, 176, 116, 43, 240, 132, 223, 203, 52, 118, 109, 169, 209, 4,
		20, 58, 222, 17, 50, 156, 83, 242, 254, 207, 195, 122, 36, 232, 96, 105,
		170, 160, 161, 98, 84, 30, 224, 100, 16, 0, 163, 117, 138, 230, 9, 221,
		135, 131, 205, 144, 115, 246, 157, 191, 82, 216, 200, 198, 129, 111, 19, 99,
		233, 167, 159, 188, 41, 249, 47, 180, 120, 6, 231, 113, 212, 171, 136, 141,
		114, 185, 248, 172, 54, 42, 60, 241, 64, 211, 187, 67, 21, 173, 119, 128,
		130, 236, 39, 229, 133, 53, 12, 65, 239, 147, 25, 33, 14, 78, 101, 189,
		184, 143, 235, 206, 48, 95, 197, 26, 225, 202, 71, 61, 1, 214, 86, 77,
		13, 102, 204, 45, 18, 32, 177, 153, 76, 194, 126, 5, 183, 49, 23, 215,
		88, 97, 27, 28, 15, 22, 24, 34, 68, 178, 181, 145, 8, 168, 252, 80,
		208, 125, 137, 151, 91, 149, 255, 210, 196, 72, 247, 219, 3, 218, 63, 148,
		92, 2, 74, 51, 103, 243, 127, 226, 155, 38, 55, 59, 150, 75, 190, 46,
		121, 140, 110, 142, 245, 182, 253, 89, 152, 106, 70, 186, 37, 66, 162, 250,
		7, 85, 238, 10, 73, 104, 56, 164, 40, 123, 201, 193, 227, 244, 199, 158
	];

	// Use S-boxes on each byte
	let mut in_bytes: [u8; 8] = input.to_be_bytes();
	in_bytes[0] = SBOX1[in_bytes[0] as usize]; // Using usize, as you can't index arrays with u8
	in_bytes[1] = SBOX2[in_bytes[1] as usize];
	in_bytes[2] = SBOX3[in_bytes[2] as usize];
	in_bytes[3] = SBOX4[in_bytes[3] as usize];
	
	in_bytes[4] = SBOX2[in_bytes[4] as usize];
	in_bytes[5] = SBOX3[in_bytes[5] as usize];
	in_bytes[6] = SBOX4[in_bytes[6] as usize];
	in_bytes[7] = SBOX1[in_bytes[7] as usize];

	// Convert back to u64
	u64::from_be_bytes(in_bytes)
}

// Camellia's FL Function
fn logic_transform( input: u64, key: u64 ) -> u64 {
	// Message and key splitting
	let (input_left, input_right) = split_32(input);
	let (key_left, key_right) = split_32(key);

	// Logic transform
	let out_right = (( input_left & key_left ).rotate_left(1)) ^ input_right;
	let out_left = (out_right | key_right) ^ input_left;

	// Halfs are combined into a 64-bit value
	return (out_left as u64) << 32 | out_right as u64;
}

fn inverse_logic_transform( input: u64, key: u64 ) -> u64 {
	// Message and key splitting
	let (input_left, input_right) = split_32(input);
	let (key_left, key_right) = split_32(key);

	let out_left = (input_right | key_right) ^ input_left;
	let out_right = (( out_left & key_left ).rotate_left(1)) ^ input_right;

	// Halfs are combined into a 64-bit value
	return (out_left as u64) << 32 | out_right as u64;
}

// Convenience splitter for 64-bit values into two 32-bit values
fn split_32( message: u64 ) -> (u32, u32) {
	( (message >> 32) as u32, message as u32 )
}

fn split_64( message: u128 ) -> (u64, u64) {
	( (message >> 64) as u64, message as u64 )
}