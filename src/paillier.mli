
type private_key = {g:Z.t; n:Z.t ; n2:Z.t ; p: Z.t ; q: Z.t ; lambda: Z.t ; mu: Z.t }
type public_key = {g:Z.t; n:Z.t ; n2:Z.t ; }

val gen_secret_key : Z.t -> Z.t -> private_key

val gen_public_key : private_key -> public_key

val encrypt : public_key -> Z.t -> Z.t 

val decrypt : private_key -> Z.t -> Z.t

val add : public_key -> Z.t -> Z.t -> Z.t
