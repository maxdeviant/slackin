import gleam/bit_array
import gleam/string

pub fn hash_equals(a: String, b: String) -> Bool {
  case string.length(a) == string.length(b) {
    True -> do_hash_equals(a, b)
    False -> False
  }
}

@target(erlang)
@external(erlang, "slackin_ffi", "hash_equals")
fn do_hash_equals(a: String, b: String) -> Bool

pub fn sha256(key: String, data: String) -> Result(String, Nil) {
  do_hash_hmac_sha256(key, data)
  |> binary_to_hex
}

@target(erlang)
@external(erlang, "slackin_ffi", "hash_hmac_sha256")
fn do_hash_hmac_sha256(key: String, data: String) -> BitArray

fn binary_to_hex(binary: BitArray) -> Result(String, Nil) {
  binary
  |> do_binary_to_hex
  |> bit_array.to_string
}

@target(erlang)
@external(erlang, "slackin_ffi", "binary_to_hex")
fn do_binary_to_hex(binary: BitArray) -> BitArray
