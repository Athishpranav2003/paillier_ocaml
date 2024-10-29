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
  let decrypted = decrypt secret_key (encrypt public_key msg) in
  assert (msg = decrypted);
  let msg = Z.one in
  let decrypted = decrypt secret_key (encrypt public_key msg) in
  assert (msg = decrypted);
  let msg_1,msg_2 = Z.one,Z.(~$2) in
  let encrypted_1 = encrypt public_key msg_1 in
  let encrypted_2 = encrypt public_key msg_2 in
  let encrypted = add public_key encrypted_1 encrypted_2 in
  let decrypted = decrypt secret_key encrypted in
  assert (decrypted = Z.add msg_1 msg_2);
