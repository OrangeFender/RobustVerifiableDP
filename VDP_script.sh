rm VDP_Output.txt
cargo run --package robust_verifiable_dp --example VDP_stages --release --no-default-features --features m5_t2 >> VDP_Output.txt
cargo run --package robust_verifiable_dp --example VDP_stages --release --no-default-features --features m5_t4 >> VDP_Output.txt
cargo run --package robust_verifiable_dp --example VDP_stages --release --no-default-features --features m3_t1 >> VDP_Output.txt
cargo run --package robust_verifiable_dp --example VDP_stages --release --no-default-features --features m3_t2 >> VDP_Output.txt

