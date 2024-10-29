open Paillier

let () = Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna)

let rec prime ?g ?(msb = 1) bits =
  let p = Z.(nextprime @@ Mirage_crypto_pk.Z_extra.gen (shift_left one bits)) in
  if p < Z.(one lsl bits) then p else prime ?g ~msb bits
let numbits = 4095

let (p,q) = (prime ~msb:2 (numbits/2), prime ~msb:2 (numbits-numbits/2))

let secret_key = gen_secret_key p q 

let public_key = gen_public_key secret_key 

let _ =
  let msg = Z.zero in
  let decrypted = decrypt secret_key (encrypt public_key msg ()) in
  assert (msg = decrypted);
  let msg = Z.one in
  let decrypted = decrypt secret_key (encrypt public_key msg ()) in
  assert (msg = decrypted);
  let r_1 = Mirage_crypto_pk.Z_extra.gen public_key.n in
  let r_2 = Mirage_crypto_pk.Z_extra.gen public_key.n in
  let encrypted_1 = encrypt public_key Z.one ~r:r_1 () in
  let encrypted_2 = encrypt public_key Z.(~$2) ~r:r_2 () in
  let encrypted = add public_key encrypted_1 encrypted_2 in
  let encrypted_true = encrypt public_key Z.(~$3) ~r:(Z.(rem (mul r_1 r_2) public_key.n)) () in
  assert (encrypted = encrypted_true)
