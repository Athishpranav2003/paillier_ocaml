(lang dune 3.16)
(generate_opam_files true)

(name paillier)
(source (github Athishpranav2003/paillier-ocaml))
(authors "Athish Pranav Dharmalingam")
(maintainers "Athish Pranav Dharmalingam <Athish Pranav Dharmalingam>")

(package
 (name paillier)
 (allow_empty)
 (synopsis "Paillier implementation OCaml")
 (description "Paillier implementation OCaml")

(depends (zarith (>= 1.4))
         (mirage-crypto (>= 1.1.0))
)
)
