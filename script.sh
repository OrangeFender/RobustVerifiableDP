rm Output.txt

example_name="$1"


echo "m5_t2" >> Output.txt
cargo run --package robust_verifiable_dp --example $example_name --release --no-default-features --features m5_t2 >> Output.txt
echo "m5_t4" >> Output.txt
cargo run --package robust_verifiable_dp --example $example_name --release --no-default-features --features m5_t4 >> Output.txt
echo "m3_t1" >> Output.txt
cargo run --package robust_verifiable_dp --example $example_name --release --no-default-features --features m3_t1 >> Output.txt
echo "m3_t2" >> Output.txt
cargo run --package robust_verifiable_dp --example $example_name --release --no-default-features --features m3_t2 >> Output.txt

