import srp

salt, vkey = srp.create_salted_verification_key('alice', '@lice_$', hash_alg=srp.SHA256, ng_type=srp.NG_2048)
print("Salt:", salt.hex())
print("Verifier:", vkey.hex())
