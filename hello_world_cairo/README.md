## Sample commands to run

starkli signer keystore new demo-key.json
starkli account oz init demo-account.json --keystore ./demo-key.json
starkli account deploy demo-account.json --keystore ./demo-key.json

starkli declare target/dev/hello_world_cairo_contract.sierra.json --account demo-account.json --keystore ./demo-key.json --compiler-version 2.0.1 --network goerli-1 --watch

starkli deploy HASH --account demo-account.json --keystore ./demo-key.json --network goerli-1 --watch
