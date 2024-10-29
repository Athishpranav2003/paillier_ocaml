type private_key = {g:Z.t; n:Z.t ; n2:Z.t ; p: Z.t ; q: Z.t ; lambda: Z.t ; mu: Z.t }

type public_key = {g:Z.t; n:Z.t ; n2:Z.t ; }



let gen_secret_key p q =
  let _ = if p = q then failwith "p and q must be different" in
  let _ = if Z.(gcd (mul p q) (mul (pred p) (pred q)) <> one) then failwith "p and q must be prime" in
  let n = Z.mul p q in
  let n2 = Z.mul n n in
  let g = Z.succ n in
  let lambda = Z.(mul (pred p) (pred q)) in
  let mu = Z.invert lambda n in
  {g; n; n2; p; q; lambda; mu}

let gen_public_key (priv_key:private_key) =
  {g = priv_key.g; n = priv_key.n; n2 = priv_key.n2}

let encrypt (public_key:public_key) msg ?r () =
  let get_r () = Mirage_crypto_pk.Z_extra.gen public_key.n in
  let check_r r =  Z.((r >= zero) && (r < public_key.n) && gcd r public_key.n = one) in
  let r = match r with
    | Some r -> if check_r r then r else failwith "r is not valid"
    | None -> let r = (Mirage_crypto_pk.Z_extra.gen Z.(~$2)) in if check_r r then r else get_r () in
  let gm = Z.powm public_key.g msg public_key.n2 in
  let rn = Z.powm r public_key.n public_key.n2 in
  Z.(rem (mul gm rn) public_key.n2)
  
  
let decrypt (private_key:private_key) c =
  let cn = Z.powm c private_key.lambda private_key.n2 in
  let lx = Z.(div (sub cn one) private_key.n) in
  Z.(rem (mul private_key.mu lx) private_key.n)

let add (public_key:public_key) c1 c2 =
  Z.rem (Z.mul c1 c2) public_key.n2
