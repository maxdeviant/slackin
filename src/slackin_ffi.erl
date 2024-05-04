-module(slackin_ffi).

-export([binary_to_hex/1, hash_equals/2, hash_hmac_sha256/2]).

binary_to_hex(Bin) ->
    binary:encode_hex(Bin, lowercase).

hash_equals(Hash1, Hash2) ->
    crypto:hash_equals(Hash1, Hash2).

hash_hmac_sha256(Key, Data) ->
    crypto:mac(hmac, sha256, Key, Data).
